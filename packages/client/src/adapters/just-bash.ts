/**
 * The just-bash adapter: one granted export, seen as a shell's `IFileSystem`.
 *
 * `just-bash` 3.4.2's `IFileSystem` is handed to `new Bash({ fs })`. The shell
 * runs **in the consumer**; this adapter provides only the filesystem it reads
 * and writes. A VFS adapter does not expose the remote machine's installed
 * programs, and no host command executes anywhere.
 *
 * The upstream declarations are imported **type-only**, so `tsc` checks this
 * against the installed package's own `.d.ts` and nothing of `just-bash` loads
 * at run time.
 *
 * ## `partial` and `unknown`
 *
 * `IFileSystem` documents every failure as `@throws Error`. A plain `Error` has
 * no code, no outcome and no structure, and by the time a shell has turned one
 * into a nonzero exit status and a line of stderr, nothing of it survives at
 * all. **A Bash exit code cannot express an ambiguous mutation**, and an agent
 * that read one as "the command failed, so nothing happened" would retry a
 * write that may have landed.
 *
 * So there are two surfaces, and the contract requires both:
 *
 * 1. The thrown `Error` carries the shared client's code as its message and the
 *    client's own `FilesystemError` as `cause`. The message is a code and an
 *    operation — never a path, a name or content — because a shell prints what
 *    it catches.
 * 2. `drainOperationFailures()` is the structured side channel. Every ambiguous
 *    mutation this adapter observes is recorded there with its operation, code,
 *    virtual path, outcome and acknowledged bytes; a completed `bash.exec()` is
 *    then reported together with what it drains. The scope is bounded at 64
 *    entries per execution and **overflow is reported explicitly** rather than
 *    dropping the sixty-fifth silently.
 *
 * An AI tool wrapper reporting a failed execution must include the drained
 * result and must never infer "safe to retry" from a nonzero exit code.
 *
 * ## Named limits of this view
 *
 * * `appendFile` is unsupported, so shell `>>` fails with a documented
 *   filesystem error. Gate 5 does not advertise `nativeAppend`; emulating it
 *   with a stat and a positioned write is the race the contract forbids.
 * * `getAllPaths()` returns the empty array, which upstream permits. It is
 *   synchronous and this filesystem is remote, so the alternative would be a
 *   synchronous network call. Glob discovery that depends on it finds nothing;
 *   globs resolved through `readdir` work.
 * * `lstat` is `stat`. The shared client's `stat` has no no-follow option, and
 *   `symlinks` is absent from the default feature set, so on a supported export
 *   there is no link for the two to disagree about. Named rather than implied.
 * * `readFileBytes` is **not** implemented. Its return type is a branded
 *   `ByteString` that only upstream's own constructors can produce, and forging
 *   the brand would be a type assertion. Upstream declares the method optional
 *   for exactly this case and falls back to `readFileBuffer`.
 * * `symlink`, `link` and `readlink` require their advertised features and
 *   otherwise fail explicitly.
 *
 * ## `Bash` must be constructed with one defense-in-depth exclusion
 *
 * just-bash 3.4.2 monkey-patches dangerous globals for the duration of a script
 * and **blocks `globalThis.setTimeout`**. A remote filesystem cannot work under
 * that: the shared client arms a timer for every request's deadline, so the
 * first `cat` fails with `security violation: globalThis.setTimeout is blocked
 * during script execution` before any 9P message is sent. This was found by
 * running the real `Bash`; nothing in the adapter plan anticipated it.
 *
 * Upstream's own violation message names the remedy for exactly this case —
 * "If this access is required by trusted host-runtime code, add "setTimeout" to
 * defenseInDepth.excludeViolationTypes" — and a `fs` the application injected
 * *is* trusted host-runtime code rather than anything the script supplied. So a
 * supported construction is:
 *
 * ```ts
 * const bash = new Bash({
 *   fs: new TunnelJustBashFilesystem({ remote }),
 *   cwd: '/',
 *   defenseInDepth: { excludeViolationTypes: [...REQUIRED_DEFENSE_EXCLUSIONS] },
 * });
 * ```
 *
 * `setTimeout` is the **only** exclusion needed: every other global the box
 * patches stays patched, and read, write, pipeline, redirect, `cp`, `mv` and
 * `find` transcripts all pass with just this one. Widening it further is a
 * consumer's decision and is not this adapter's to recommend.
 */

import type {
  BufferEncoding,
  CpOptions,
  FileContent,
  FsStat,
  IFileSystem,
  MkdirOptions,
  RmOptions,
} from 'just-bash';
import type { RemoteFilesystem, Stat } from '../filesystem.ts';
import { FilesystemError } from '../errors.ts';
import { PathRefusal, validatePath, type PathBounds } from '../paths.ts';
import { failureRecord, isAmbiguous, summarize, type OperationFailure } from './outcomes.ts';

/**
 * Three of `IFileSystem`'s own option types are **not re-exported** by
 * `just-bash` 3.4.2's package root.
 *
 * `ReadFileOptions`, `WriteFileOptions` and `DirentEntry` are declared in
 * `dist/fs/interface.d.ts` and used in the interface's signatures, but the
 * root's `export type { … }` list omits them and the package's `exports` map
 * exposes only `.` and `./browser`, so there is no deep import either. This is
 * an upstream packaging gap, recorded in `docs/filesystem-adapters.md` rather
 * than worked around by copying the declarations: a local substitute is exactly
 * what `docs/testing.md` says cannot satisfy contract compilation.
 *
 * They are instead **extracted from the installed interface**, so they are the
 * upstream types by construction and a change to them is a type error here.
 */
type ReadFileOptions = NonNullable<Parameters<IFileSystem['readFile']>[1]>;
type WriteFileOptions = NonNullable<Parameters<IFileSystem['writeFile']>[2]>;
type DirentEntry = Awaited<
  ReturnType<NonNullable<IFileSystem['readdirWithFileTypes']>>
>[number];

/** "Limit 64 entries per execution and report overflow explicitly." */
export const MAX_OPERATION_FAILURES = 64;

/**
 * The defense-in-depth violation types a `Bash` over this filesystem must
 * exclude. See the module comment for why there is exactly one.
 *
 * Typed as `SecurityViolationType[]` at the call site rather than here, so this
 * constant carries no upstream type and the offline suite can read it.
 */
export const REQUIRED_DEFENSE_EXCLUSIONS = ['setTimeout'] as const;

export interface DrainedFailures {
  entries: OperationFailure[];
  /** How many records were refused once the bound was reached. Never silent. */
  dropped: number;
}

export interface TunnelJustBashFilesystemOptions {
  remote: RemoteFilesystem;
  /**
   * The per-execution record bound. Defaults to `MAX_OPERATION_FAILURES`.
   *
   * Configurable because the bound is the behaviour under test and the
   * consumer-side tag quota is 64 as well — so reaching the default by running
   * 65 ambiguous mutations at once is not something a session can do.
   */
  maxOperationFailures?: number | undefined;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export class TunnelJustBashFilesystem implements IFileSystem {
  private readonly remote: RemoteFilesystem;
  private readonly bounds: PathBounds;
  private readonly maxFailures: number;
  private failures: OperationFailure[] = [];
  private dropped = 0;

  constructor(options: TunnelJustBashFilesystemOptions) {
    this.remote = options.remote;
    this.maxFailures = options.maxOperationFailures ?? MAX_OPERATION_FAILURES;
    this.bounds = {
      maxPathBytes: options.remote.descriptor.limits.maxPathBytes,
      maxPathComponents: options.remote.descriptor.limits.maxPathComponents,
    };
  }

  /**
   * Take the structured failures recorded since the last drain.
   *
   * "Concurrent Bash executions use separate wrapper/error scopes, even if they
   * borrow one connection": one wrapper is one scope, so a consumer running two
   * executions concurrently gives each its own `TunnelJustBashFilesystem` over
   * the same client. Sharing one wrapper across two executions and draining
   * once would mix their records, and this method cannot tell them apart.
   */
  drainOperationFailures(): DrainedFailures {
    const entries = this.failures;
    const dropped = this.dropped;
    this.failures = [];
    this.dropped = 0;
    return { entries, dropped };
  }

  /* ------------------------------------------------------------------ *
   * Reads
   * ------------------------------------------------------------------ */

  async readFile(path: string, options?: ReadFileOptions | BufferEncoding): Promise<string> {
    return await this.guard('readFile', async () => {
      const bytes = await this.remote.readFile(this.check(path));
      const encoding = typeof options === 'string' ? options : options?.encoding ?? 'utf8';
      return decodeAs(bytes, encoding);
    });
  }

  async readFileBuffer(path: string): Promise<Uint8Array> {
    return await this.guard('readFileBuffer', async () => await this.remote.readFile(this.check(path)));
  }

  async exists(path: string): Promise<boolean> {
    try {
      await this.remote.stat(this.check(path));
      return true;
    } catch (error) {
      if (error instanceof FilesystemError && error.code === 'ENOENT') {
        return false;
      }
      throw this.raise('exists', error);
    }
  }

  async stat(path: string): Promise<FsStat> {
    return await this.guard('stat', async () => toFsStat(await this.remote.stat(this.check(path))));
  }

  /** The same call as `stat`: see the module comment's named limit. */
  async lstat(path: string): Promise<FsStat> {
    return await this.guard('lstat', async () => toFsStat(await this.remote.stat(this.check(path))));
  }

  async readdir(path: string): Promise<string[]> {
    return await this.guard('readdir', async () => {
      const names: string[] = [];
      for await (const entry of this.remote.readDirectory(this.check(path))) {
        names.push(entry.name);
      }
      return names;
    });
  }

  async readdirWithFileTypes(path: string): Promise<DirentEntry[]> {
    return await this.guard('readdirWithFileTypes', async () => {
      const out: DirentEntry[] = [];
      for await (const entry of this.remote.readDirectory(this.check(path))) {
        out.push({
          name: entry.name,
          isFile: entry.kind === 'file',
          isDirectory: entry.kind === 'directory',
          isSymbolicLink: entry.kind === 'symlink',
        });
      }
      return out;
    });
  }

  async realpath(path: string): Promise<string> {
    return await this.guard('realpath', async () => {
      // Nothing to resolve: `symlinks` is absent by default, so a path that
      // validates is already canonical for this export. When the feature is
      // advertised this would need `readlink` chasing, which is refused rather
      // than approximated.
      const virtual = this.check(path);
      if (this.remote.descriptor.features.symlinks) {
        throw new FilesystemError({
          code: 'ENOTSUP',
          operation: 'realpath',
          path: virtual,
          outcome: 'not_started',
          retryable: false,
        });
      }
      await this.remote.stat(virtual);
      return virtual;
    });
  }

  /* ------------------------------------------------------------------ *
   * Writes
   * ------------------------------------------------------------------ */

  async writeFile(path: string, content: FileContent, _options?: WriteFileOptions | BufferEncoding): Promise<void> {
    await this.guard('writeFile', async () => {
      const virtual = this.check(path);
      await this.remote.writeFile(virtual, toBytes(content, _options));
    });
  }

  /** Unsupported: this endpoint advertises no atomic append. Shell `>>` fails. */
  async appendFile(path: string, _content: FileContent, _options?: WriteFileOptions | BufferEncoding): Promise<void> {
    await this.guard('appendFile', async () => {
      const virtual = this.check(path);
      throw new FilesystemError({
        code: 'ENOTSUP',
        operation: 'appendFile',
        path: virtual,
        outcome: 'not_started',
        retryable: false,
      });
    });
  }

  async mkdir(path: string, options?: MkdirOptions): Promise<void> {
    await this.guard('mkdir', async () => {
      await this.remote.mkdir(this.check(path), {
        ...(options?.recursive === true ? { recursive: true } : {}),
      });
    });
  }

  async rm(path: string, options?: RmOptions): Promise<void> {
    await this.guard('rm', async () => {
      await this.remote.remove(this.check(path), {
        ...(options?.recursive === true ? { recursive: true } : {}),
        ...(options?.force === true ? { force: true } : {}),
      });
    });
  }

  async cp(src: string, dest: string, options?: CpOptions): Promise<void> {
    await this.guard('cp', async () => {
      const source = this.check(src);
      const destination = this.check(dest);
      const stat = await this.remote.stat(source);
      if (stat.kind !== 'file') {
        // A recursive directory copy is not composed here: see the Mastra
        // adapter's `copyFile` for the same refusal and the same reason.
        throw new FilesystemError({
          code: options?.recursive === true ? 'ENOTSUP' : 'EISDIR',
          operation: 'cp',
          path: source,
          outcome: 'not_started',
          retryable: false,
        });
      }
      await this.remote.copy(source, destination);
    });
  }

  /** "Ensure `mv` fails across roots/devices and never silently becomes copy-and-delete." */
  async mv(src: string, dest: string): Promise<void> {
    await this.guard('mv', async () => {
      await this.remote.rename(this.check(src), this.check(dest));
    });
  }

  async chmod(path: string, mode: number): Promise<void> {
    await this.guard('chmod', async () => {
      await this.remote.chmod(this.check(path), mode);
    });
  }

  async utimes(path: string, atime: Date, mtime: Date): Promise<void> {
    await this.guard('utimes', async () => {
      await this.remote.utimes(this.check(path), atime.getTime(), mtime.getTime());
    });
  }

  async symlink(target: string, linkPath: string): Promise<void> {
    await this.guard('symlink', async () => {
      await this.remote.symlink(target, this.check(linkPath));
    });
  }

  /** `hardLinks` is absent by default, so the shared client has no `link` at all. */
  async link(_existingPath: string, newPath: string): Promise<void> {
    await this.guard('link', async () => {
      const virtual = this.check(newPath);
      throw new FilesystemError({
        code: 'ENOTSUP',
        operation: 'link',
        path: virtual,
        outcome: 'not_started',
        retryable: false,
      });
    });
  }

  async readlink(path: string): Promise<string> {
    return await this.guard('readlink', async () => await this.remote.readlink(this.check(path)));
  }

  /* ------------------------------------------------------------------ *
   * Synchronous members
   * ------------------------------------------------------------------ */

  /**
   * Pure lexical resolution with root clamping, and no network call.
   *
   * "The just-bash adapter retains its upstream pure lexical root-clamping
   * behavior before calling the shared client." `..` above the root clamps to
   * the root, which is just-bash's own contract for a shell — and is **not**
   * confinement: the shared client then refuses any `..` it is handed, and the
   * device enforces confinement regardless of both.
   */
  resolvePath(base: string, path: string): string {
    const absolute = path.startsWith('/') ? path : `${base.endsWith('/') ? base : `${base}/`}${path}`;
    const out: string[] = [];
    for (const part of absolute.split('/')) {
      if (part === '' || part === '.') {
        continue;
      }
      if (part === '..') {
        out.pop();
        continue;
      }
      out.push(part);
    }
    return `/${out.join('/')}`;
  }

  /** The upstream-permitted empty result. See the module comment. */
  getAllPaths(): string[] {
    return [];
  }

  /* ------------------------------------------------------------------ *
   * Internals
   * ------------------------------------------------------------------ */

  private check(path: string): string {
    validatePath(path, this.bounds);
    return path;
  }

  private async guard<T>(operation: string, body: () => Promise<T>): Promise<T> {
    try {
      return await body();
    } catch (error) {
      throw this.raise(operation, error);
    }
  }

  /**
   * Record the outcome, then throw what a shell can carry.
   *
   * The recording happens first and unconditionally for an ambiguous mutation,
   * because the `Error` that leaves this method is about to lose it.
   */
  private raise(operation: string, error: unknown): Error {
    if (isAmbiguous(error)) {
      const record = failureRecord(operation, error);
      if (record !== undefined) {
        if (this.failures.length >= this.maxFailures) {
          this.dropped += 1;
        } else {
          this.failures.push(record);
        }
      }
    }
    if (error instanceof FilesystemError || error instanceof PathRefusal) {
      // The message is a code and an operation. A shell prints what it catches,
      // so a path in here would be a path in a transcript and in whatever reads
      // one; the caller already knows the path it asked for, and the structured
      // channel carries it for the cases where a tool needs it.
      const raised = new Error(summarize(error), { cause: error });
      raised.name = 'TunnelFilesystemError';
      return raised;
    }
    return error instanceof Error ? error : new Error(String(error));
  }
}

function toFsStat(stat: Stat): FsStat {
  if (stat.size > BigInt(Number.MAX_SAFE_INTEGER)) {
    // "range-check conversion to just-bash numbers and `Date` values".
    throw new FilesystemError({
      code: 'EFBIG',
      operation: 'stat:size',
      outcome: 'not_started',
      retryable: false,
    });
  }
  return {
    isFile: stat.kind === 'file',
    isDirectory: stat.kind === 'directory',
    isSymbolicLink: stat.kind === 'symlink',
    mode: stat.mode,
    size: Number(stat.size),
    mtime: new Date(stat.modifiedAtMs),
    // `dev`, `ino` and `identity` are deliberately absent: "File
    // identity/metadata must not leak host inode, UID, or directory details",
    // and the qid is scoped to this session rather than being a stable identity
    // a shell could compare across sessions.
  };
}

function toBytes(content: FileContent, options: WriteFileOptions | BufferEncoding | undefined): Uint8Array {
  if (typeof content !== 'string') {
    return content;
  }
  const encoding = typeof options === 'string' ? options : options?.encoding ?? 'utf8';
  switch (encoding) {
    case 'base64':
    case 'hex':
    case 'latin1':
    case 'binary':
    case 'ascii':
      return new Uint8Array(Buffer.from(content, encoding === 'binary' ? 'latin1' : encoding));
    default:
      return encoder.encode(content);
  }
}

function decodeAs(bytes: Uint8Array, encoding: BufferEncoding): string {
  switch (encoding) {
    case 'base64':
    case 'hex':
    case 'latin1':
    case 'binary':
    case 'ascii':
      return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString(
        encoding === 'binary' ? 'latin1' : encoding,
      );
    default:
      // "invalid UTF-8 must not corrupt byte reads" — a text read of binary
      // content is a text read, and a caller wanting the bytes uses
      // `readFileBuffer`, which is why that method exists.
      return decoder.decode(bytes);
  }
}
