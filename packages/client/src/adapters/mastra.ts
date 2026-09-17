/**
 * The Mastra adapter: one granted export, seen as a `WorkspaceFilesystem`.
 *
 * `@mastra/core` 1.65.0 defines `WorkspaceFilesystem` with eleven asynchronous
 * operations, four identity properties and an optional lifecycle, and a
 * `Workspace` is constructed with an instance of it. This module implements
 * that interface over the shared client, with **type-only** imports of the
 * upstream declarations, so `tsc` checks it against the installed package's own
 * `.d.ts` and nothing of `@mastra/core` loads at run time.
 *
 * ## The interface rather than the base class, deliberately
 *
 * `docs/filesystem-adapters.md` says "preferably extending `MastraFilesystem`".
 * That class extends `MastraBase` for logger injection, so extending it is a
 * **value** import of `@mastra/core` — which would make this package's Mastra
 * entry point load the framework, and would put a framework dependency inside a
 * package whose whole shape is that it has none. Upstream sanctions the other
 * half of the choice in the class's own documentation: "External providers can
 * extend this class to get logger support, or implement the WorkspaceFilesystem
 * interface directly if they don't need logging." This implements the
 * interface. The cost is named rather than hidden: **no Mastra logger reaches
 * this adapter**, so its diagnostics go through its own return values and its
 * errors, not through `this.logger`.
 *
 * ## The error classes are injected
 *
 * Mastra's errors are runtime classes and its tools branch on them with
 * `instanceof`. Building a structurally similar object would not be one. So the
 * consumer hands over the classes from its own `@mastra/core/workspace`:
 *
 * ```ts
 * import * as workspace from '@mastra/core/workspace';
 * const filesystem = new TunnelMastraFilesystem({ remote, errors: workspace });
 * ```
 *
 * ## `partial` and `unknown`
 *
 * Mastra's `FilesystemError(message, code, path)` has a free-form `code` and no
 * outcome concept. An ambiguous mutation therefore becomes a plain
 * `FilesystemError` with code `TUNNEL_PARTIAL` or `TUNNEL_UNKNOWN` and the
 * shared client's own error as `cause`. Two things follow, and both are
 * deliberate:
 *
 * * Such a failure is **never** reported as one of Mastra's semantic errors.
 *   `FileNotFoundError` after a half-applied write would tell a caller the file
 *   is absent; `FileExistsError` would tell it the write was refused. Neither
 *   is true, and both read as "nothing happened".
 * * A caller switching on Mastra's own error classes falls through to a
 *   default. That is the correct outcome and it is the limit of what this
 *   interface can express: there is no field a Mastra tool already reads that
 *   would carry `partial`.
 *
 * ## Paths in messages
 *
 * Mastra's `FilesystemError` takes a `path` and renders it into `message`. The
 * payload-free rule forbids a **host** path, a host identity or content; the
 * path here is the *virtual* path the caller itself supplied, which the shared
 * client already carries as a field for the same reason. Nothing host-derived
 * is ever passed, and a `readdir` name that came from the device is only
 * combined into a virtual path the caller could have written itself.
 */

import type {
  CopyOptions,
  FileContent,
  FileEntry,
  FileStat,
  FilesystemInfo,
  ListOptions,
  ProviderStatus,
  ReadOptions,
  RemoveOptions,
  WorkspaceFilesystem,
  WriteOptions,
} from '@mastra/core/workspace';

import type { DirectoryEntry, RemoteFilesystem, Stat } from '../filesystem.ts';
import { FilesystemError } from '../errors.ts';
import { PathRefusal, validatePath, type PathBounds } from '../paths.ts';
import { isAmbiguous, summarize, withAppliedFloor } from './outcomes.ts';

/** The subset of `@mastra/core/workspace`'s error classes this adapter raises. */
export interface MastraErrorClasses {
  FilesystemError: new (message: string, code: string, path: string) => Error;
  FileNotFoundError: new (path: string) => Error;
  DirectoryNotFoundError: new (path: string) => Error;
  FileExistsError: new (path: string) => Error;
  IsDirectoryError: new (path: string) => Error;
  NotDirectoryError: new (path: string) => Error;
  DirectoryNotEmptyError: new (path: string) => Error;
  PermissionError: new (path: string, operation: string) => Error;
  StaleFileError: new (path: string, expectedMtime: Date, actualMtime: Date) => Error;
}

/**
 * How a requested `expectedMtime` is treated.
 *
 * `'reject'` is the default and refuses the condition before any mutation,
 * because the endpoint's `conditionalWrites` is false and there is no atomic
 * primitive behind it. Mastra's own read tracking supplies the condition
 * internally, so **this default does not support ordinary read-then-edit tools
 * on a writable mount**, and that is the point of making it explicit.
 *
 * `'check-before-write'` reproduces Mastra's advisory behaviour: a stat, a
 * comparison of the same millisecond value, then the write. It is a documented
 * race and **not** a conditional write, compare-and-swap, or lost-update
 * protection. It does not change `conditionalWrites`.
 */
export type MtimePolicy = 'reject' | 'check-before-write';

export interface TunnelMastraFilesystemOptions {
  remote: RemoteFilesystem;
  errors: MastraErrorClasses;
  mtimePolicy?: MtimePolicy | undefined;
  id?: string | undefined;
  displayName?: string | undefined;
}

const encoder = new TextEncoder();

export class TunnelMastraFilesystem implements WorkspaceFilesystem {
  readonly id: string;
  readonly name = 'TunnelMastraFilesystem';
  readonly provider = 'agent-tunnel';
  readonly readOnly: boolean;
  readonly displayName: string;
  readonly description =
    'A granted remote export reached over the Agent Tunnel filesystem endpoint.';
  status: ProviderStatus = 'pending';
  error?: string;

  private readonly remote: RemoteFilesystem;
  private readonly errors: MastraErrorClasses;
  private readonly bounds: PathBounds;
  readonly mtimePolicy: MtimePolicy;

  constructor(options: TunnelMastraFilesystemOptions) {
    this.remote = options.remote;
    this.errors = options.errors;
    this.mtimePolicy = options.mtimePolicy ?? 'reject';
    this.id = options.id ?? `agent-tunnel:${options.remote.descriptor.deviceId}/${options.remote.descriptor.serviceId}`;
    this.displayName = options.displayName ?? 'Agent Tunnel export';
    this.readOnly = options.remote.descriptor.root.readOnly;
    this.bounds = {
      maxPathBytes: options.remote.descriptor.limits.maxPathBytes,
      maxPathComponents: options.remote.descriptor.limits.maxPathComponents,
    };
  }

  /* ------------------------------------------------------------------ *
   * Lifecycle. It manages this wrapper's state, never the shared client.
   * ------------------------------------------------------------------ */

  async init(): Promise<void> {
    // The connection was made by the application and is **borrowed**. Init
    // records that this wrapper is usable; it does not connect, and `destroy`
    // does not close, because another borrower may still hold the same client.
    this.status = this.remote.state === 'ready' ? 'ready' : 'error';
    if (this.status === 'error') {
      this.error = `client ${this.remote.state}`;
    }
    await Promise.resolve();
  }

  async destroy(): Promise<void> {
    this.status = 'destroyed';
    await Promise.resolve();
  }

  getInfo(): FilesystemInfo {
    return {
      id: this.id,
      name: this.name,
      provider: this.provider,
      status: this.status,
      readOnly: this.readOnly,
      metadata: {
        // `FilesystemInfo` has no `displayName` or `description` field — those
        // live on the filesystem instance itself — so the UI-facing strings are
        // not repeated here and the provider-specific block carries only what
        // upstream has no field for.
        displayName: this.displayName,
        // "expose `createdAtSource:'mtime-fallback'` through provider
        // metadata/instructions. This is a compatibility convention, not a
        // historical creation-time claim."
        createdAtSource: this.remote.descriptor.features.birthTime ? 'birth-time' : 'mtime-fallback',
        mtimePolicy: this.mtimePolicy,
        conditionalWrites: false,
        nativeAppend: this.remote.descriptor.features.nativeAppend,
        operations: [...this.remote.descriptor.operations],
      },
      ...(this.error === undefined ? {} : { error: this.error }),
    };
  }

  getInstructions(): string {
    const created = this.remote.descriptor.features.birthTime
      ? 'createdAt is the host birth time.'
      : 'createdAt is the modification time, as a documented compatibility fallback; it is not a creation time.';
    const timestamps =
      this.mtimePolicy === 'reject'
        ? 'A write carrying expectedMtime is refused before any mutation: this endpoint has no conditional write.'
        : 'A write carrying expectedMtime is checked with a preceding stat. This is advisory and races a concurrent writer; it is not a conditional write.';
    return [
      'Paths are absolute POSIX paths inside one granted export. There is no host path and no base path.',
      'Parent traversal, dot segments, repeated separators, backslashes, colons and reserved device names are refused, never repaired.',
      'appendFile is unsupported: this endpoint does not advertise an atomic append and this adapter will not emulate one.',
      created,
      timestamps,
    ].join(' ');
  }

  /** "Filesystems without symlink or alias semantics can return the input path unchanged." */
  async realpath(path: string): Promise<string> {
    this.check(path);
    return await Promise.resolve(path);
  }

  /** Remote and in-memory filesystems have no disk path. Upstream permits `undefined`. */
  resolveAbsolutePath(): string | undefined {
    return undefined;
  }

  /* ------------------------------------------------------------------ *
   * The eleven operations
   * ------------------------------------------------------------------ */

  async readFile(path: string, options?: ReadOptions): Promise<string | Buffer> {
    return await this.guard('readFile', path, async () => {
      const bytes = await this.remote.readFile(this.check(path));
      const buffer = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      // "Return Buffer by default from `readFile`, or decode the requested Node
      // encoding." A copy is taken for the Buffer view so the caller's value
      // does not alias the client's chunk.
      return options?.encoding === undefined
        ? Buffer.from(buffer)
        : buffer.toString(options.encoding);
    });
  }

  async writeFile(path: string, content: FileContent, options?: WriteOptions): Promise<void> {
    await this.guard('writeFile', path, async () => {
      const virtual = this.check(path);
      await this.applyMtimePolicy(virtual, options?.expectedMtime);
      // "Writes create parents by default unless `recursive:false`." That makes
      // this a composite **at this layer**, and the directories it makes are a
      // change to the export that a failing write knows nothing about.
      const applied = options?.recursive === false ? false : await this.ensureParent(virtual);
      // "Honor `overwrite:false` using exclusive creation" — the shared client
      // sends `Tlcreate`, which this profile makes exclusive whatever the flag
      // word said. It is never an exists-then-create race.
      try {
        await this.remote.writeFile(virtual, toBytes(content), {
          overwrite: options?.overwrite !== false,
        });
      } catch (error) {
        throw withAppliedFloor(error, 'writeFile', virtual, applied);
      }
    });
  }

  /**
   * Required by the interface and unsupported by the endpoint.
   *
   * Gate 5 does not advertise `nativeAppend`, because the two supported hosts
   * disagree about whether `pwrite` honours its offset on an appending
   * descriptor. The alternatives are both forbidden: a stat followed by a
   * positioned write is the race `docs/filesystem-api.md` rules out, and a
   * read-modify-write would silently turn an append into a whole-file replace.
   * So this is an explicit unsupported-operation error — "An absent capability
   * must never become fabricated metadata, a silently ignored option, or a
   * successful no-op."
   */
  async appendFile(path: string, _content: FileContent): Promise<void> {
    await this.guard('appendFile', path, async () => {
      this.check(path);
      throw new FilesystemError({
        code: 'ENOTSUP',
        operation: 'appendFile',
        path,
        outcome: 'not_started',
        retryable: false,
      });
    });
  }

  async deleteFile(path: string, options?: RemoveOptions): Promise<void> {
    await this.guard('deleteFile', path, async () => {
      const virtual = this.check(path);
      const kind = await this.kindOf(virtual, options?.force === true);
      if (kind === undefined) {
        return;
      }
      if (kind !== 'file') {
        throw new FilesystemError({
          code: 'EISDIR',
          operation: 'deleteFile',
          path: virtual,
          outcome: 'not_started',
          retryable: false,
        });
      }
      await this.remote.remove(virtual, { ...(options?.force === true ? { force: true } : {}) });
    });
  }

  /**
   * A regular-file copy only.
   *
   * `CopyOptions.recursive` would ask for a directory copy, which the shared
   * client does not compose and the contract declines to promise: "The
   * supported baseline does not promise bounded cross-provider copy through
   * that upstream implementation; certify it separately or keep those
   * operations disabled." A directory source is refused rather than
   * half-copied.
   */
  async copyFile(src: string, dest: string, options?: CopyOptions): Promise<void> {
    await this.guard('copyFile', src, async () => {
      const source = this.check(src);
      const destination = this.check(dest);
      const kind = await this.kindOf(source, false);
      if (kind !== 'file') {
        throw new FilesystemError({
          code: options?.recursive === true ? 'ENOTSUP' : 'EISDIR',
          operation: 'copyFile',
          path: source,
          outcome: 'not_started',
          retryable: false,
        });
      }
      const applied = await this.ensureParent(destination);
      try {
        await this.remote.copy(source, destination, { overwrite: options?.overwrite !== false });
      } catch (error) {
        throw withAppliedFloor(error, 'copyFile', destination, applied);
      }
    });
  }

  /**
   * A native in-export rename, never copy-and-delete.
   *
   * `overwrite: false` cannot be honoured: the endpoint has no exclusive
   * rename, and an existence check before the rename is the race the contract
   * forbids. "reject unsupported move-without-overwrite semantics rather than
   * doing a racy existence check" — so it is refused.
   */
  async moveFile(src: string, dest: string, options?: CopyOptions): Promise<void> {
    await this.guard('moveFile', src, async () => {
      const source = this.check(src);
      const destination = this.check(dest);
      if (options?.overwrite === false) {
        throw new FilesystemError({
          code: 'ENOTSUP',
          operation: 'moveFile:overwrite',
          path: destination,
          outcome: 'not_started',
          retryable: false,
        });
      }
      await this.remote.rename(source, destination);
    });
  }

  async mkdir(path: string, options?: { recursive?: boolean }): Promise<void> {
    await this.guard('mkdir', path, async () => {
      await this.remote.mkdir(this.check(path), {
        ...(options?.recursive === true ? { recursive: true } : {}),
      });
    });
  }

  async rmdir(path: string, options?: RemoveOptions): Promise<void> {
    await this.guard('rmdir', path, async () => {
      const virtual = this.check(path);
      const kind = await this.kindOf(virtual, options?.force === true);
      if (kind === undefined) {
        return;
      }
      if (kind !== 'directory') {
        throw new FilesystemError({
          code: 'ENOTDIR',
          operation: 'rmdir',
          path: virtual,
          outcome: 'not_started',
          retryable: false,
        });
      }
      await this.remote.remove(virtual, {
        ...(options?.recursive === true ? { recursive: true } : {}),
        ...(options?.force === true ? { force: true } : {}),
      });
    });
  }

  /**
   * Immediate children, or a bounded recursive listing.
   *
   * **Three rules here are the pinned `LocalFilesystem`'s and not inventions**,
   * because a Mastra tool reads this result and has no other way to address
   * what it finds:
   *
   * * A nested entry's `name` is **prefixed with its subpath** — the reference
   *   builds `` `${entry.name}/${e.name}` `` as it returns up each level. Without
   *   it, `/a/x.txt` and `/b/x.txt` both come back as `x.txt` and a tool can
   *   address neither.
   * * A directory entry is pushed **before** its contents, and an extension
   *   filter applies to **files only**, so a filtered recursive listing keeps
   *   the structure the names are relative to rather than returning orphans.
   * * An extension matches `extname(name)` by **equality**, against the pattern
   *   with or without its leading dot — so `.ts` and `ts` both select `x.ts`
   *   and `s` selects nothing. A suffix test would have let `s` match.
   *
   * "Materialized directory/file results fail on limits rather than silently
   * truncate": the entry budget is the descriptor's and a listing that reaches
   * it is an error, not a short array that reads as a complete directory.
   */
  async readdir(path: string, options?: ListOptions): Promise<FileEntry[]> {
    return await this.guard('readdir', path, async () => {
      const root = this.check(path);
      const extensions = options?.extension === undefined
        ? undefined
        : (Array.isArray(options.extension) ? options.extension : [options.extension]);
      const limits = this.remote.descriptor.limits;
      const maxDepth = options?.maxDepth ?? limits.maxTraversalDepth;
      const out: FileEntry[] = [];
      let seen = 0;
      const visit = async (at: string, prefix: string, depth: number): Promise<void> => {
        for await (const entry of this.remote.readDirectory(at)) {
          seen += 1;
          if (seen > limits.maxTraversalEntries) {
            throw new FilesystemError({
              code: 'EFBIG',
              operation: 'readdir',
              path: root,
              outcome: 'not_started',
              retryable: false,
            });
          }
          const record = toEntry(entry, `${prefix}${entry.name}`);
          if (record.type === 'directory' || matchesExtension(entry.name, extensions)) {
            out.push(record);
          }
          if (
            options?.recursive === true &&
            entry.kind === 'directory' &&
            depth + 1 <= maxDepth
          ) {
            await visit(
              at === '/' ? `/${entry.name}` : `${at}/${entry.name}`,
              `${prefix}${entry.name}/`,
              depth + 1,
            );
          }
        }
      };
      await visit(root, '', 0);
      return out;
    });
  }

  async exists(path: string): Promise<boolean> {
    try {
      await this.remote.stat(this.check(path));
      return true;
    } catch (error) {
      // Only a confirmed absence is `false`. A denial or an offline device
      // throws, because reporting them as absence would tell a Mastra tool the
      // export does not hold a file it may very well hold.
      if (error instanceof FilesystemError && error.code === 'ENOENT') {
        return false;
      }
      throw this.translate('exists', path, error);
    }
  }

  async stat(path: string): Promise<FileStat> {
    return await this.guard('stat', path, async () => {
      const virtual = this.check(path);
      const stat = await this.remote.stat(virtual);
      if (stat.kind === 'symlink') {
        // "Unknown node types fail instead of becoming fake regular files."
        // `FileStat.type` is `'file' | 'directory'` and has no third word.
        throw new FilesystemError({
          code: 'ENOTSUP',
          operation: 'stat:kind',
          path: virtual,
          outcome: 'not_started',
          retryable: false,
        });
      }
      return this.toFileStat(virtual, stat);
    });
  }

  /* ------------------------------------------------------------------ *
   * Internals
   * ------------------------------------------------------------------ */

  private toFileStat(path: string, stat: Stat): FileStat {
    const name = path === '/' ? '/' : (path.split('/').pop() as string);
    // "Mastra requires `createdAt` and numeric sizes." A 64-bit size that does
    // not fit a JavaScript number fails rather than rounding into a `number`
    // that is not the size.
    if (stat.size > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new FilesystemError({
        code: 'EFBIG',
        operation: 'stat:size',
        path,
        outcome: 'not_started',
        retryable: false,
      });
    }
    return {
      name,
      path,
      type: stat.kind === 'directory' ? 'directory' : 'file',
      size: stat.kind === 'directory' ? 0 : Number(stat.size),
      // The fallback, stated in `getInfo().metadata.createdAtSource` and in the
      // instructions. It is a compatibility convention, not a birth time.
      createdAt: new Date(stat.createdAtMs ?? stat.modifiedAtMs),
      modifiedAt: new Date(stat.modifiedAtMs),
    };
  }

  /**
   * The timestamp policy, applied **before** any parent creation or truncation.
   *
   * `'check-before-write'` compares the same millisecond value `stat()` returns
   * in `modifiedAt` with `expectedMtime.getTime()`, throws the real
   * `StaleFileError` on a mismatch, and proceeds when the file is missing —
   * which is what the pinned `LocalFilesystem` does. Other stat errors are
   * preserved rather than swallowed into a stale-file verdict. A writer between
   * the check and the write, or a change inside timestamp precision, is not
   * detected; the remote round trip makes that window longer than a local one.
   */
  private async applyMtimePolicy(path: string, expected: Date | undefined): Promise<void> {
    if (expected === undefined) {
      return;
    }
    if (this.mtimePolicy === 'reject') {
      throw new FilesystemError({
        code: 'ENOTSUP',
        operation: 'writeFile:expectedMtime',
        path,
        outcome: 'not_started',
        retryable: false,
      });
    }
    let stat: Stat;
    try {
      stat = await this.remote.stat(path);
    } catch (error) {
      if (error instanceof FilesystemError && error.code === 'ENOENT') {
        return;
      }
      throw error;
    }
    if (stat.modifiedAtMs !== expected.getTime()) {
      throw new this.errors.StaleFileError(path, expected, new Date(stat.modifiedAtMs));
    }
  }

  /**
   * Create a path's parent directories, reporting whether that changed
   * anything.
   *
   * The count comes from `mkdir` itself — a chain whose components all existed
   * returns zero — so the floor is set by what was actually applied and never
   * by a preliminary `stat`, which would be the exists-then-act race the
   * contract forbids.
   */
  private async ensureParent(path: string): Promise<boolean> {
    const parent = parentOf(path);
    if (parent === '/' || !this.remote.supports('mkdir')) {
      return false;
    }
    return (await this.remote.mkdir(parent, { recursive: true })) > 0;
  }

  private async kindOf(path: string, force: boolean): Promise<Stat['kind'] | undefined> {
    try {
      return (await this.remote.stat(path)).kind;
    } catch (error) {
      if (force && error instanceof FilesystemError && error.code === 'ENOENT') {
        return undefined;
      }
      throw error;
    }
  }

  private check(path: string): string {
    validatePath(path, this.bounds);
    return path;
  }

  private async guard<T>(operation: string, path: string, body: () => Promise<T>): Promise<T> {
    try {
      return await body();
    } catch (error) {
      throw this.translate(operation, path, error);
    }
  }

  /**
   * The shared client's error vocabulary, in Mastra's.
   *
   * The ambiguous outcomes come first and deliberately: a `partial` write that
   * happened to fail with `ENOENT` must not become `FileNotFoundError`, which
   * a caller reads as "the file is not there and nothing was written".
   */
  private translate(operation: string, path: string, error: unknown): Error {
    const E = this.errors;
    if (error instanceof PathRefusal) {
      return new E.FilesystemError(`${error.rule} (${operation})`, 'TUNNEL_PATH_REFUSED', path);
    }
    if (!(error instanceof FilesystemError)) {
      // One of the injected classes passes through whole: `StaleFileError` from
      // the check-before-write policy is Mastra's own answer and rewriting it
      // would destroy the timestamps a tool reads off it.
      if (error instanceof E.FilesystemError) {
        return error;
      }
      // Anything else is reduced to its constructor name. An internal
      // `TypeError`'s text is not this package's to forward into a framework's
      // logger, where it could carry a value that was never meant to leave.
      const raised = new E.FilesystemError(summarize(error), 'TUNNEL_INTERNAL', path);
      Object.defineProperty(raised, 'cause', { value: error, configurable: true, writable: true });
      return raised;
    }
    const at = error.path ?? path;
    if (isAmbiguous(error)) {
      const code = error.outcome === 'partial' ? 'TUNNEL_PARTIAL' : 'TUNNEL_UNKNOWN';
      const raised = new E.FilesystemError(summarize(error), code, at);
      // Mastra's constructor takes no cause, and the distinction between
      // `partial` and `unknown` lives nowhere else in this interface, so the
      // client's own error is attached as one. `code` above is the only field a
      // Mastra consumer can branch on without it.
      Object.defineProperty(raised, 'cause', { value: error, configurable: true, writable: true });
      return raised;
    }
    switch (error.code) {
      case 'ENOENT':
        return operation === 'readdir' || operation === 'rmdir'
          ? new E.DirectoryNotFoundError(at)
          : new E.FileNotFoundError(at);
      case 'EEXIST':
        return new E.FileExistsError(at);
      case 'EISDIR':
        return new E.IsDirectoryError(at);
      case 'ENOTDIR':
        return new E.NotDirectoryError(at);
      case 'ENOTEMPTY':
        return new E.DirectoryNotEmptyError(at);
      case 'EACCES':
      case 'EPERM':
      case 'EROFS':
        return new E.PermissionError(at, operation);
      default: {
        const raised = new E.FilesystemError(summarize(error), `TUNNEL_${error.code}`, at);
        Object.defineProperty(raised, 'cause', { value: error, configurable: true, writable: true });
        return raised;
      }
    }
  }
}

function parentOf(path: string): string {
  const cut = path.lastIndexOf('/');
  return cut <= 0 ? '/' : path.slice(0, cut);
}

function toBytes(content: FileContent): Uint8Array {
  // `FileContent` is `string | Buffer | Uint8Array`, and a `Buffer` **is** a
  // `Uint8Array`, so there is no third case. An earlier round carried an
  // `ArrayBufferView` branch that could not be reached and that would have
  // ignored `byteOffset`/`byteLength` if it had been.
  return typeof content === 'string' ? encoder.encode(content) : content;
}

function toEntry(entry: DirectoryEntry, name: string): FileEntry {
  if (entry.kind === 'symlink') {
    // `FileEntry` has an `isSymlink` flag, so a link can be reported honestly
    // here — unlike `FileStat.type`, which has no word for one. The target is
    // not read: `readlink` needs the `symlinks` feature and a `read` grant.
    return { name, type: 'file', isSymlink: true };
  }
  return { name, type: entry.kind };
}

/**
 * The pinned `LocalFilesystem`'s extension rule, which is an **equality** test
 * on the extension and not a suffix test on the name.
 *
 * Upstream: `extensions.some((e) => e === ext || e === ext.slice(1))` over
 * `nodePath.extname(entry.name)`. So `.ts` and `ts` both select `x.ts`, and
 * `s` selects nothing — where an `endsWith` would have matched it. Applied to
 * the **bare** name rather than the subpath-prefixed one, because that is what
 * upstream extracts the extension from.
 */
function matchesExtension(name: string, extensions: string[] | undefined): boolean {
  if (extensions === undefined) {
    return true;
  }
  const extension = extnameOf(name);
  return extensions.some((pattern) => pattern === extension || pattern === extension.slice(1));
}

/** `node:path`'s `extname`, for the cases a filename can present. */
function extnameOf(name: string): string {
  const dot = name.lastIndexOf('.');
  // A leading dot is the whole name — `.gitignore` has no extension — and a
  // name with no dot has none either. Both are what `extname` returns.
  return dot <= 0 ? '' : name.slice(dot);
}
