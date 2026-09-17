/**
 * Wiring for the adapter suites: a real loopback socket, and the framework
 * classes each adapter is handed.
 *
 * The socket half is the same harness the client's own tests use, with the same
 * warning attached: it is a peer that speaks the wire and is **not** a relay and
 * not a device. Nothing observed through it is evidence about
 * `crates/tunnel-relay` or `crates/tunnel-fs-provider`.
 *
 * The framework half is deliberately **local**. `npm test` runs offline with
 * `node_modules` deleted, so these suites cannot load `files-sdk` or
 * `@mastra/core`; they pass stand-in classes with the same constructor shapes
 * and assert exactly which arguments each adapter chose. The real classes are
 * used in `test/peers/`, which runs after an install, and the adapters' own
 * sources import the real declarations as types — so what the stand-ins stand
 * in for is checked by `tsc`, not assumed here.
 */

import { strict as assert } from 'node:assert';

import { connectFilesystem, type RemoteFilesystem } from '../../src/filesystem.ts';
import type { Descriptor } from '../../src/descriptor.ts';
import { descriptorFixture } from '../harness/descriptor.ts';
import { startEndpoint, type Endpoint, type ServerConnection } from '../harness/endpoint.ts';
import { FakeProvider } from '../harness/provider.ts';
import type { MastraErrorClasses } from '../../src/adapters/mastra.ts';

const open: Endpoint[] = [];

/** Close every endpoint a suite opened. Call from `after`. */
export async function closeAll(): Promise<void> {
  for (const endpoint of open.splice(0)) {
    await endpoint.close();
  }
}

export interface Wired {
  remote: RemoteFilesystem;
  provider: FakeProvider;
  connection: ServerConnection;
}

export async function wire(
  seed: Record<string, string | Uint8Array> = {},
  overrides: Partial<Descriptor> = {},
  configure: (provider: FakeProvider) => void = () => {},
): Promise<Wired> {
  const provider = new FakeProvider(seed);
  configure(provider);
  const descriptor = descriptorFixture(overrides);
  const endpoint = await startEndpoint(
    { descriptor, onRequest: provider.handle },
    descriptor.limits.maxMessageBytes,
  );
  open.push(endpoint);
  const remote = await connectFilesystem({
    endpoint: endpoint.url,
    token: () => 'synthetic-consumer-token',
    allowInsecureLoopback: true,
  });
  const connection = endpoint.connections[0];
  assert.ok(connection !== undefined);
  return { remote, provider, connection };
}

export async function waitFor(predicate: () => boolean, label = 'condition'): Promise<void> {
  for (let attempt = 0; attempt < 500; attempt += 1) {
    if (predicate()) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
  throw new Error(`timed out waiting for ${label}`);
}

/* ---------------------------------------------------------------------- *
 * Files SDK stand-in
 * ---------------------------------------------------------------------- */

export interface FilesErrorOptions {
  aborted?: boolean;
  timedOut?: boolean;
  permanent?: boolean;
  applied?: boolean;
  appliedEtag?: string;
}

/**
 * The same constructor shape as `files-sdk`'s `FilesError`, recording what it
 * was given.
 *
 * `applied` is the field this whole suite watches: upstream it means a
 * conditional mutation **committed**, and an adapter that set it for a merely
 * ambiguous outcome would be making a claim nobody can support. Every
 * assertion about it here is that it stayed unset.
 */
export type StandInFilesErrorCode = 'NotFound' | 'Unauthorized' | 'Conflict' | 'ReadOnly' | 'Provider';

export class StandInFilesError extends Error {
  readonly code: StandInFilesErrorCode;
  readonly aborted: boolean;
  readonly timedOut: boolean;
  readonly permanent: boolean;
  readonly applied: boolean;
  // Optional rather than `string | undefined`, matching upstream's own
  // declaration under `exactOptionalPropertyTypes`.
  readonly appliedEtag?: string;

  constructor(
    code: StandInFilesErrorCode,
    message: string,
    cause?: unknown,
    opts?: FilesErrorOptions,
  ) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'FilesError';
    this.code = code;
    this.aborted = opts?.aborted ?? false;
    this.timedOut = opts?.timedOut ?? false;
    this.permanent = opts?.permanent ?? false;
    this.applied = opts?.applied ?? false;
    if (opts?.appliedEtag !== undefined) {
      this.appliedEtag = opts.appliedEtag;
    }
  }
}

/**
 * Upstream's own retry predicate, copied from `files-sdk` 2.4.0's
 * `internal/retry.ts` so a suite that cannot load the package can still ask the
 * question the package asks:
 *
 * ```js
 * attempt < maxAttempts && error.code === "Provider" && !(error.aborted || error.permanent)
 * ```
 *
 * This is a **test oracle**, not an interface substitute: the adapter compiles
 * against the real `FilesError` and `test/peers/` runs the real `Files` wrapper
 * with retries enabled and counts dispatches.
 */
export function upstreamWouldRetry(error: StandInFilesError): boolean {
  return error.code === 'Provider' && !(error.aborted || error.permanent);
}

/* ---------------------------------------------------------------------- *
 * Mastra stand-ins
 * ---------------------------------------------------------------------- */

class StandInMastraFilesystemError extends Error {
  readonly code: string;
  readonly path: string;

  constructor(message: string, code: string, path: string) {
    super(message);
    this.name = 'FilesystemError';
    this.code = code;
    this.path = path;
  }
}

/** One of the single-path Mastra error classes, by its own name and code. */
function pathError(name: string, code: string): new (path: string) => Error {
  return class extends StandInMastraFilesystemError {
    constructor(path: string) {
      super(code, code, path);
      this.name = name;
    }
  };
}

export const standInMastraErrors: MastraErrorClasses = {
  FilesystemError: StandInMastraFilesystemError,
  FileNotFoundError: pathError('FileNotFoundError', 'FILE_NOT_FOUND'),
  DirectoryNotFoundError: pathError('DirectoryNotFoundError', 'DIRECTORY_NOT_FOUND'),
  FileExistsError: pathError('FileExistsError', 'FILE_EXISTS'),
  IsDirectoryError: pathError('IsDirectoryError', 'IS_DIRECTORY'),
  NotDirectoryError: pathError('NotDirectoryError', 'NOT_DIRECTORY'),
  DirectoryNotEmptyError: pathError('DirectoryNotEmptyError', 'DIRECTORY_NOT_EMPTY'),
  PermissionError: class extends StandInMastraFilesystemError {
    readonly operation: string;
    constructor(path: string, operation: string) {
      super('PERMISSION', 'PERMISSION', path);
      this.name = 'PermissionError';
      this.operation = operation;
    }
  },
  StaleFileError: class extends StandInMastraFilesystemError {
    readonly expectedMtime: Date;
    readonly actualMtime: Date;
    constructor(path: string, expectedMtime: Date, actualMtime: Date) {
      super('STALE_FILE', 'STALE_FILE', path);
      this.name = 'StaleFileError';
      this.expectedMtime = expectedMtime;
      this.actualMtime = actualMtime;
    }
  },
};
