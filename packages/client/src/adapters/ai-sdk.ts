/**
 * The AI SDK adapter: a managed file-object view over one granted export.
 *
 * `@ai-sdk/provider` 4.0.11 — the exact version `ai` 7.0.94 depends on —
 * defines `FilesV4`, which `ai.uploadFile({ api, ... })` accepts directly. This
 * module implements it over the shared client, with **type-only** imports of
 * the upstream declarations, so `tsc` checks it against the installed package's
 * own `.d.ts` and nothing of `ai` or `@ai-sdk/provider` loads at run time.
 *
 * It is a **file-object API, not a directory API**. There is no listing, no
 * path input, and no way to turn an existing path into a reference.
 *
 * ## What a reference is, and what it is not
 *
 * A reference is an alias for the virtual path this adapter assigned, **not an
 * immutable file identity or version**. If another authorized writer replaces
 * that path, metadata and download see the new occupant and delete removes the
 * new occupant; a rename away yields absence. A QID or stat preflight cannot
 * make deletion conditional on identity, so none is attempted. Use a dedicated
 * upload directory.
 *
 * ## `partial` and `unknown`
 *
 * `FilesV4` has `warnings: Array<SharedV4Warning>` on every **success** and
 * nothing at all on a failure — the call rejects and the thrown value's shape
 * is the provider's business. So:
 *
 * * `uploadFile` throws. A reference is returned "only after confirmed
 *   completion", and an upload whose outcome is `partial` or `unknown` has not
 *   completed. The path it was writing is recorded in
 *   `incompleteUploads()` for the application's own cleanup, because "failure
 *   is not success just because a file exists".
 * * `deleteFile` throws rather than answering `deleted: false`. That field is
 *   the one place an ambiguous outcome could be flattened into a false claim:
 *   `false` says the provider did not delete it, and after an `unknown` nobody
 *   knows that. `true` would be worse.
 * * `getFileMetadata` and `downloadFile` are reads and cannot be ambiguous;
 *   they throw their failures unchanged.
 *
 * The thrown value is the shared client's own `FilesystemError`, so `outcome`
 * survives for a caller that looks. **There is no AI SDK field that carries
 * it**, and `warnings` cannot: it rides on results, and these calls have none.
 */

import type {
  FilesV4,
  FilesV4DeleteFileCallOptions,
  FilesV4DeleteFileResult,
  FilesV4DownloadFileCallOptions,
  FilesV4DownloadFileResult,
  FilesV4GetFileMetadataCallOptions,
  FilesV4GetFileMetadataResult,
  FilesV4UploadFileCallOptions,
  FilesV4UploadFileResult,
  SharedV4ProviderReference,
  SharedV4Warning,
} from '@ai-sdk/provider';

import type { RemoteFilesystem } from '../filesystem.ts';
import { FilesystemError } from '../errors.ts';
import { validatePath, type PathBounds } from '../paths.ts';
import { isAmbiguous } from './outcomes.ts';

/** The provider key a reference is filed under. Never an OpenAI or Anthropic id. */
export const PROVIDER_KEY = 'agent-tunnel';
/** "maximum 256 references, all charged to its quota". */
export const MAX_REFERENCES = 256;
/** Display metadata is bounded; it is advisory and never a path selector. */
export const MAX_FILENAME_BYTES = 255;

export interface FilesApiOptions {
  remote: RemoteFilesystem;
  /**
   * The writable virtual directory uploads are created in.
   *
   * Required and explicit: there is no default, because a default would pick a
   * directory in somebody's export without being asked.
   */
  uploadDirectory: string;
  maxReferences?: number | undefined;
}

interface Reference {
  path: string;
  filename: string | undefined;
  mediaType: string;
  byteSize: number;
  createdAtMs: number;
}

/** The FilesV4 instance, plus the two things its interface has no place for. */
export type TunnelFilesApi = FilesV4 & {
  /**
   * Paths this adapter created or began creating and could not confirm.
   *
   * "Track partial uploads and their owned paths for explicit cleanup." The
   * application cleans them up under its own grant; nothing here deletes them,
   * because deleting after an `unknown` would be a second ambiguous mutation.
   */
  incompleteUploads(): string[];
  /**
   * Drop this adapter's references.
   *
   * "References survive scheduled data rotation but expire when the
   * adapter/session closes… Closing an adapter does not silently delete them."
   * The files stay; the aliases stop resolving.
   */
  close(): void;
};

export function createFilesApi(options: FilesApiOptions): TunnelFilesApi {
  const remote = options.remote;
  const bounds: PathBounds = {
    maxPathBytes: remote.descriptor.limits.maxPathBytes,
    maxPathComponents: remote.descriptor.limits.maxPathComponents,
  };
  const directory = options.uploadDirectory;
  validatePath(directory, bounds);
  if (remote.descriptor.root.readOnly) {
    // "A read-only export rejects required upload and does not advertise it as
    // a useful upload destination." Construction fails rather than producing an
    // object whose only required method can never succeed.
    throw new FilesystemError({
      code: 'EROFS',
      operation: 'createFilesApi',
      path: directory,
      outcome: 'not_started',
      retryable: false,
    });
  }
  const ceiling = options.maxReferences ?? MAX_REFERENCES;
  const references = new Map<string, Reference>();
  const incomplete = new Set<string>();

  const refuse = (code: FilesystemError['code'], operation: string, path?: string): never => {
    throw new FilesystemError({
      code,
      operation,
      ...(path === undefined ? {} : { path }),
      outcome: 'not_started',
      retryable: false,
    });
  };

  /** Only references this adapter minted. A foreign provider key is refused. */
  const resolve = (
    file: SharedV4ProviderReference,
    operation: string,
    headers: Record<string, string | undefined> | undefined,
  ): { id: string; entry: Reference } => {
    if (headers !== undefined && Object.keys(headers).length > 0) {
      // "Reject foreign provider keys and nonempty per-call header overrides
      // that could change identity." There is no HTTP request to put them on,
      // so accepting them would be accepting something that goes nowhere.
      refuse('ENOTSUP', `${operation}:headers`);
    }
    const id = file[PROVIDER_KEY];
    if (typeof id !== 'string') {
      refuse('EINVAL', `${operation}:reference`);
    }
    const entry = references.get(id as string);
    if (entry === undefined) {
      // Another adapter's, another principal's, another session's, or one this
      // adapter has closed. All four are the same answer and none of them is a
      // lookup against somebody else's map.
      refuse('ENOENT', `${operation}:reference`);
    }
    return { id: id as string, entry: entry as Reference };
  };

  const api: TunnelFilesApi = {
    specificationVersion: 'v4',
    provider: 'agent-tunnel.files',

    incompleteUploads(): string[] {
      return [...incomplete];
    },

    close(): void {
      references.clear();
    },

    async uploadFile(call: FilesV4UploadFileCallOptions): Promise<FilesV4UploadFileResult> {
      if (references.size >= ceiling) {
        // "On overload reject before creating a file. No implicit oldest-file
        // deletion." The refusal happens here, before a name is chosen.
        refuse('RESOURCE_EXHAUSTED', 'uploadFile');
      }
      if (call.filename !== undefined && new TextEncoder().encode(call.filename).byteLength > MAX_FILENAME_BYTES) {
        refuse('EINVAL', 'uploadFile:filename');
      }
      const id = opaqueId();
      // An unpredictable name in the configured directory. `filename` is
      // **display metadata**, never a path selector: a caller that could choose
      // the name could choose any name in the directory.
      const path = `${directory === '/' ? '' : directory}/${id}`;
      validatePath(path, bounds);
      incomplete.add(path);
      let byteSize = 0;
      try {
        const chunks = await callChunks(call);
        const counted = async function* (): AsyncGenerator<Uint8Array> {
          for await (const chunk of chunks) {
            byteSize += chunk.byteLength;
            yield chunk;
          }
        };
        // Exclusive creation. The id is unpredictable, so a collision is a
        // failure rather than a silent replacement of somebody's file.
        await remote.writeStream(path, counted(), {
          overwrite: false,
          ...(call.abortSignal === undefined ? {} : { signal: call.abortSignal }),
        });
      } catch (error) {
        // The reference is **not** minted. A caller gets the client's error with
        // its outcome intact, and the path stays in `incompleteUploads()`
        // whether the write is known to have failed or is `unknown`.
        if (!isAmbiguous(error)) {
          // A write that provably did nothing leaves no file to clean up. An
          // ambiguous one does, and stays listed.
          incomplete.delete(path);
        }
        throw error;
      }
      incomplete.delete(path);
      const createdAtMs = Date.now();
      references.set(id, {
        path,
        filename: call.filename,
        mediaType: call.mediaType,
        byteSize,
        createdAtMs,
      });
      return {
        providerReference: { [PROVIDER_KEY]: id },
        mediaType: call.mediaType,
        ...(call.filename === undefined ? {} : { filename: call.filename }),
        byteSize,
        createdAt: new Date(createdAtMs),
        // No `expiresAt`: nothing here deletes a file on a schedule, and a
        // retention date this adapter does not enforce would be a promise.
        warnings: aliasWarnings(),
      };
    },

    async getFileMetadata(
      call: FilesV4GetFileMetadataCallOptions,
    ): Promise<FilesV4GetFileMetadataResult> {
      const { id, entry } = resolve(call.file, 'getFileMetadata', call.headers);
      // Observed now, from the current occupant of the path. The upload's own
      // `filename` and `mediaType` are advisory and may no longer describe it.
      const stat = await remote.stat(entry.path, {
        ...(call.abortSignal === undefined ? {} : { signal: call.abortSignal }),
      });
      if (stat.size > BigInt(Number.MAX_SAFE_INTEGER)) {
        refuse('EFBIG', 'getFileMetadata', entry.path);
      }
      return {
        providerReference: { [PROVIDER_KEY]: id },
        ...(entry.filename === undefined ? {} : { filename: entry.filename }),
        mediaType: entry.mediaType,
        byteSize: Number(stat.size),
        createdAt: new Date(stat.createdAtMs ?? entry.createdAtMs),
        warnings: [
          ...aliasWarnings(),
          {
            type: 'compatibility',
            feature: 'display-metadata',
            details:
              'filename and mediaType are the values supplied at upload. They are advisory and are not stored on the file.',
          },
        ],
      };
    },

    async downloadFile(call: FilesV4DownloadFileCallOptions): Promise<FilesV4DownloadFileResult> {
      const { entry } = resolve(call.file, 'downloadFile', call.headers);
      const iterator = remote
        .readStream(entry.path, {
          ...(call.abortSignal === undefined ? {} : { signal: call.abortSignal }),
        })
        [Symbol.asyncIterator]();
      return await Promise.resolve({
        content: new ReadableStream<Uint8Array>({
          async pull(controller) {
            try {
              const next = await iterator.next();
              if (next.done === true) {
                controller.close();
                return;
              }
              controller.enqueue(next.value);
            } catch (error) {
              controller.error(error);
            }
          },
          async cancel() {
            await iterator.return?.(undefined);
          },
        }),
        mediaType: entry.mediaType,
        warnings: aliasWarnings(),
      });
    },

    async deleteFile(call: FilesV4DeleteFileCallOptions): Promise<FilesV4DeleteFileResult> {
      const { id, entry } = resolve(call.file, 'deleteFile', call.headers);
      // Removes the **current occupant** of the path. There is no conditional
      // delete and no identity check that could make one; a QID read before the
      // unlink would be a race wearing the name of a guarantee.
      await remote.remove(entry.path, {
        ...(call.abortSignal === undefined ? {} : { signal: call.abortSignal }),
      });
      references.delete(id);
      return {
        providerReference: { [PROVIDER_KEY]: id },
        deleted: true,
        warnings: aliasWarnings(),
      };
    },
  };

  return api;
}

/**
 * The one warning every call carries.
 *
 * It is `compatibility` rather than `unsupported` because the behaviour works —
 * it is just not the object-identity behaviour a caller used to a managed file
 * provider will assume.
 */
function aliasWarnings(): SharedV4Warning[] {
  return [
    {
      type: 'compatibility',
      feature: 'file-reference-identity',
      details:
        'A reference is an alias for an assigned virtual path, not an immutable file identity. Another authorized writer can replace or rename what it resolves to.',
    },
  ];
}

async function callChunks(
  call: FilesV4UploadFileCallOptions,
): Promise<AsyncIterable<Uint8Array> | Iterable<Uint8Array>> {
  const data = call.data;
  if (data.type === 'text') {
    return [new TextEncoder().encode(data.text)];
  }
  if (data.type === 'stream') {
    return streamChunks(data.stream);
  }
  if (data.data instanceof Uint8Array) {
    return [data.data];
  }
  return [decodeBase64Strict(data.data)];
}

async function* streamChunks(stream: ReadableStream<Uint8Array>): AsyncGenerator<Uint8Array> {
  const reader = stream.getReader();
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

/**
 * Base64, decoded **strictly**.
 *
 * `Buffer.from(text, 'base64')` ignores characters outside the alphabet and
 * accepts truncated input, so a caller's corrupted string would become a
 * shorter file rather than an error. "Accept bytes, strictly decoded base64,
 * UTF-8 text, or bounded streams" is the contract, and this is the strict half:
 * the alphabet and padding are checked, and the decode is required to
 * round-trip.
 */
export function decodeBase64Strict(text: string): Uint8Array {
  if (!/^[A-Za-z0-9+/]*={0,2}$/u.test(text) || text.length % 4 !== 0) {
    throw new FilesystemError({
      code: 'EINVAL',
      operation: 'uploadFile:base64',
      outcome: 'not_started',
      retryable: false,
    });
  }
  const bytes = new Uint8Array(Buffer.from(text, 'base64'));
  if (Buffer.from(bytes).toString('base64') !== text) {
    throw new FilesystemError({
      code: 'EINVAL',
      operation: 'uploadFile:base64',
      outcome: 'not_started',
      retryable: false,
    });
  }
  return bytes;
}

/** An unpredictable file name. Not a counter, and not derived from any input. */
function opaqueId(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

// The live directory tools live beside `FilesV4` on the same subpath: one is a
// file-object API and the other a directory view, and a consumer of either
// reaches both through `@agent-tunnel/client/ai-sdk`.
export {
  createFilesystemTools,
  DEFAULT_MAX_ENTRIES,
  DEFAULT_MAX_READ_BYTES,
  DEFAULT_MAX_WRITE_BYTES,
  TOOL_NAMES,
  type FilesystemToolName,
  type FilesystemTools,
  type FilesystemToolsOptions,
  type ToolFailure,
} from './ai-sdk-tools.ts';
