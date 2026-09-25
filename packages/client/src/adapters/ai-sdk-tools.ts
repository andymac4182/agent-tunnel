/**
 * The AI SDK live directory tools: gate 6's seventh component.
 *
 * `docs/filesystem-adapters.md` ("Live directory tools"): "Provide bounded
 * `read`, `list`, `write` and other granted tools over the shared client, with
 * input schemas and abort propagation. Tool outputs carry explicit `outcome`
 * for partial/unknown mutations and byte/truncation metadata. Credentials,
 * endpoint, user and export are closed-over trusted context; the model cannot
 * choose them."
 *
 * `createFilesystemTools({ remote })` returns an `ai` 7.0.94 `ToolSet` to pass
 * straight to `generateText({ tools })` or `streamText({ tools })`. Like every
 * adapter in this package it imports its framework **by type only**: each
 * tool's input schema is a Standard Schema v1 object written out here, with its
 * own `validate` and a JSON Schema converter — the shape `ai`'s own `asSchema`
 * accepts for a non-Zod vendor — so nothing of `ai` loads at run time and `tsc`
 * checks every tool against the installed `Tool` declaration.
 *
 * ## What the model can and cannot choose
 *
 * The model chooses a **virtual path** inside the export and, for a write, the
 * text. It cannot choose the endpoint, the token, the export or the grant: they
 * are the `remote` this factory closes over. A tool whose operation the grant
 * does not advertise is **not offered** — the model never sees `write_file` on
 * a read-only export — and a path is refused by the shared client's own gate-1
 * rules before anything is sent.
 *
 * ## Bounds
 *
 * * `read_file` returns at most `maxReadBytes` (default 64 KiB) and asks the
 *   device for **one byte more**, so `truncated` is measured from what was
 *   actually received and never inferred from a preceding `stat`, which a
 *   growing file would make wrong.
 * * `list_directory` returns at most `maxEntries` (default 256) and says
 *   `truncated` when it stopped early; it stops the directory walk rather than
 *   reading the rest and discarding it.
 * * `write_file` refuses text above `maxWriteBytes` (default 64 KiB) **before**
 *   dispatch, so an over-large write is `not_started`, never `partial`.
 *
 * ## Outcomes, and why failures are results rather than throws
 *
 * A filesystem failure is returned as `{ ok: false, code, outcome,
 * retrySafe }` so the model sees it. `outcome` is the shared client's own word;
 * `retrySafe` is `true` only for `not_started` and `failed` — never after a
 * `partial` or `unknown` mutation, which "may have happened". A caller's
 * cancellation is the one thing re-thrown: `abortSignal` is passed to every
 * request, and an aborted tool call ends the step as the AI SDK expects rather
 * than being reported to the model as a filesystem error.
 *
 * No result carries a host path, a token, or a byte of content beyond what the
 * model asked to read.
 */

import type { FlexibleSchema, Tool, ToolExecutionOptions, ToolSet } from 'ai';

import type { RemoteFilesystem, Stat } from '../filesystem.ts';
import { FilesystemError, type Outcome } from '../errors.ts';
import { PathRefusal } from '../paths.ts';
import { isAborted } from './outcomes.ts';

export const DEFAULT_MAX_READ_BYTES = 64 * 1024;
export const DEFAULT_MAX_ENTRIES = 256;
export const DEFAULT_MAX_WRITE_BYTES = 64 * 1024;

/** The tool names this factory can offer. */
export const TOOL_NAMES = ['list_directory', 'read_file', 'stat', 'write_file'] as const;
export type FilesystemToolName = (typeof TOOL_NAMES)[number];

export interface FilesystemToolsOptions {
  /** The shared client. Borrowed: never reconfigured and never closed here. */
  remote: RemoteFilesystem;
  maxReadBytes?: number | undefined;
  maxEntries?: number | undefined;
  maxWriteBytes?: number | undefined;
  /**
   * Offer no mutating tool even when the grant allows one. A narrowing the
   * application may choose; it can never widen what the grant advertises.
   */
  readOnly?: boolean | undefined;
}

/** A refused or failed call, as the model sees it. */
export interface ToolFailure {
  ok: false;
  /** The shared client's code, or a path rule, or `INVALID_INPUT`. */
  code: string;
  outcome: Outcome;
  /** `true` only when nothing can have happened. Never after `partial`/`unknown`. */
  retrySafe: boolean;
}

export interface ListDirectoryInput {
  path: string;
}
export type ListDirectoryOutput =
  | {
      ok: true;
      path: string;
      entries: { name: string; kind: 'file' | 'directory' | 'symlink' }[];
      truncated: boolean;
    }
  | ToolFailure;

export interface ReadFileInput {
  path: string;
  maxBytes?: number | undefined;
}
export type ReadFileOutput =
  | {
      ok: true;
      path: string;
      /** `utf8` when the bytes returned decode strictly; otherwise `base64`. */
      encoding: 'utf8' | 'base64';
      content: string;
      bytesReturned: number;
      truncated: boolean;
    }
  | ToolFailure;

export interface StatInput {
  path: string;
}
export type StatOutput =
  | {
      ok: true;
      path: string;
      kind: 'file' | 'directory' | 'symlink';
      /** A decimal string: a 64-bit size does not fit a JSON number. */
      size: string;
      modifiedAt: string;
    }
  | ToolFailure;

export interface WriteFileInput {
  path: string;
  content: string;
  overwrite?: boolean | undefined;
}
export type WriteFileOutput =
  | { ok: true; path: string; bytesWritten: number; outcome: 'applied' }
  | ToolFailure;

export interface FilesystemTools extends ToolSet {
  list_directory: Tool<ListDirectoryInput, ListDirectoryOutput>;
  read_file: Tool<ReadFileInput, ReadFileOutput>;
  stat: Tool<StatInput, StatOutput>;
  write_file?: Tool<WriteFileInput, WriteFileOutput>;
}

export function createFilesystemTools(options: FilesystemToolsOptions): FilesystemTools {
  const remote = options.remote;
  const maxReadBytes = positive(options.maxReadBytes, DEFAULT_MAX_READ_BYTES, 'maxReadBytes');
  const maxEntries = positive(options.maxEntries, DEFAULT_MAX_ENTRIES, 'maxEntries');
  const maxWriteBytes = positive(options.maxWriteBytes, DEFAULT_MAX_WRITE_BYTES, 'maxWriteBytes');

  const listDirectory: Tool<ListDirectoryInput, ListDirectoryOutput> = {
    description:
      'List the immediate children of a directory in the remote export. Paths are absolute inside the export, starting with "/".',
    inputSchema: objectSchema<ListDirectoryInput>(
      { path: { type: 'string', description: 'Absolute virtual path, e.g. "/" or "/docs".' } },
      ['path'],
      (value) => ({ path: value.path }),
    ),
    execute: async (input, execution) =>
      await guarded(execution, async (signal) => {
        const entries: { name: string; kind: 'file' | 'directory' | 'symlink' }[] = [];
        let truncated = false;
        for await (const entry of remote.readDirectory(input.path, { signal })) {
          if (entries.length === maxEntries) {
            // Stop the walk: returning from the loop runs the generator's
            // `finally`, which clunks its fid, rather than reading the rest.
            truncated = true;
            break;
          }
          entries.push({ name: entry.name, kind: entry.kind });
        }
        entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
        return { ok: true, path: input.path, entries, truncated };
      }),
  };

  const readFile: Tool<ReadFileInput, ReadFileOutput> = {
    description: `Read a file from the remote export. Returns at most ${maxReadBytes} bytes; "truncated" says whether more remained.`,
    inputSchema: objectSchema<ReadFileInput>(
      {
        path: { type: 'string', description: 'Absolute virtual path of a regular file.' },
        maxBytes: {
          type: 'integer',
          minimum: 1,
          maximum: maxReadBytes,
          description: `Optional smaller bound, at most ${maxReadBytes}.`,
        },
      },
      ['path'],
      (value) => {
        const maxBytes = value.maxBytes;
        if (maxBytes !== undefined && (typeof maxBytes !== 'number' || !Number.isSafeInteger(maxBytes) || maxBytes < 1)) {
          return undefined;
        }
        return { path: value.path, maxBytes: typeof maxBytes === 'number' ? maxBytes : undefined };
      },
    ),
    execute: async (input, execution) =>
      await guarded(execution, async (signal) => {
        const limit = Math.max(1, Math.min(input.maxBytes ?? maxReadBytes, maxReadBytes));
        const chunks: Uint8Array[] = [];
        let received = 0;
        // One byte beyond the limit, so truncation is observed, not inferred.
        for await (const chunk of remote.readStream(input.path, { signal, length: limit + 1 })) {
          chunks.push(chunk);
          received += chunk.byteLength;
        }
        const truncated = received > limit;
        const bytes = new Uint8Array(Math.min(received, limit));
        let at = 0;
        for (const chunk of chunks) {
          const take = Math.min(chunk.byteLength, bytes.byteLength - at);
          bytes.set(chunk.subarray(0, take), at);
          at += take;
          if (at === bytes.byteLength) {
            break;
          }
        }
        const text = decodeStrict(bytes, truncated);
        return {
          ok: true,
          path: input.path,
          encoding: text === undefined ? 'base64' : 'utf8',
          content: text ?? Buffer.from(bytes).toString('base64'),
          bytesReturned: bytes.byteLength,
          truncated,
        };
      }),
  };

  const stat: Tool<StatInput, StatOutput> = {
    description: 'Report the kind, size and modification time of a path in the remote export.',
    inputSchema: objectSchema<StatInput>(
      { path: { type: 'string', description: 'Absolute virtual path.' } },
      ['path'],
      (value) => ({ path: value.path }),
    ),
    execute: async (input, execution) =>
      await guarded(execution, async (signal) => {
        const found: Stat = await remote.stat(input.path, { signal });
        return {
          ok: true,
          path: input.path,
          kind: found.kind,
          size: found.size.toString(),
          modifiedAt: new Date(found.modifiedAtMs).toISOString(),
        };
      }),
  };

  const tools: FilesystemTools = { list_directory: listDirectory, read_file: readFile, stat };

  // "Implement only when advertised": a write tool the grant cannot serve is
  // never offered, so a model is not invited to try it.
  const writable =
    options.readOnly !== true && !remote.descriptor.root.readOnly && remote.supports('writeFile');
  if (writable) {
    tools.write_file = {
      description: `Write UTF-8 text to a file in the remote export (at most ${maxWriteBytes} bytes). Without "overwrite": true an existing file is not replaced. A result with outcome "partial" or "unknown" may have been applied and must not be retried blindly.`,
      inputSchema: objectSchema<WriteFileInput>(
        {
          path: { type: 'string', description: 'Absolute virtual path of the file to create or replace.' },
          content: { type: 'string', description: 'The UTF-8 text to write.' },
          overwrite: { type: 'boolean', description: 'Replace an existing file. Defaults to false.' },
        },
        ['path', 'content'],
        (value) => {
          if (typeof value.content !== 'string') {
            return undefined;
          }
          if (value.overwrite !== undefined && typeof value.overwrite !== 'boolean') {
            return undefined;
          }
          return {
            path: value.path,
            content: value.content,
            overwrite: typeof value.overwrite === 'boolean' ? value.overwrite : undefined,
          };
        },
      ),
      execute: async (input, execution) =>
        await guarded(execution, async (signal) => {
          const bytes = new TextEncoder().encode(input.content);
          if (bytes.byteLength > maxWriteBytes) {
            // Refused before dispatch: nothing can have happened.
            return failure('EFBIG', 'not_started');
          }
          await remote.writeFile(input.path, bytes, { signal, overwrite: input.overwrite ?? false });
          return { ok: true, path: input.path, bytesWritten: bytes.byteLength, outcome: 'applied' };
        }),
    };
  }
  return tools;
}

/* ---------------------------------------------------------------------- *
 * Shared plumbing
 * ---------------------------------------------------------------------- */

function positive(value: number | undefined, fallback: number, name: string): number {
  if (value === undefined) {
    return fallback;
  }
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError(`${name} must be a positive integer`);
  }
  return value;
}

function failure(code: string, outcome: Outcome): ToolFailure {
  return { ok: false, code, outcome, retrySafe: outcome === 'not_started' || outcome === 'failed' };
}

/**
 * Run one tool body with the caller's abort signal, turning a filesystem
 * failure into a model-visible result and re-throwing only a cancellation.
 */
async function guarded<T>(
  execution: Pick<ToolExecutionOptions<unknown>, 'abortSignal'>,
  body: (signal: AbortSignal | undefined) => Promise<T>,
): Promise<T | ToolFailure> {
  const signal = execution.abortSignal;
  try {
    return await body(signal);
  } catch (error) {
    if (isAborted(error) || signal?.aborted === true) {
      throw error;
    }
    if (error instanceof FilesystemError) {
      return failure(error.code, error.outcome);
    }
    if (error instanceof PathRefusal) {
      return failure(error.rule, 'not_started');
    }
    throw error;
  }
}

/**
 * Strict UTF-8, so a binary file is returned as base64 rather than as text
 * with replacement characters. When the read was truncated, up to three
 * trailing bytes may be an incomplete sequence cut by the bound rather than
 * invalid text, so those are tolerated by decoding in streaming mode.
 */
function decodeStrict(bytes: Uint8Array, truncated: boolean): string | undefined {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes, { stream: truncated });
  } catch {
    return undefined;
  }
}

type JsonProperty =
  | { type: 'string'; description: string }
  | { type: 'boolean'; description: string }
  | { type: 'integer'; minimum: number; maximum: number; description: string };

/**
 * A Standard Schema v1 object with a JSON Schema converter: `ai`'s `asSchema`
 * turns it into a validating `Schema` without any `ai` value being imported.
 *
 * Validation is deliberately strict: an object, the required string `path`,
 * no unknown keys, and whatever `refine` adds. A refusal is an issue list, which
 * the AI SDK reports as an invalid tool input rather than calling `execute`.
 */
function objectSchema<T extends { path: string }>(
  properties: Record<string, JsonProperty>,
  required: string[],
  refine: (value: Record<string, unknown> & { path: string }) => T | undefined,
): FlexibleSchema<T> {
  const json = { type: 'object' as const, properties, required, additionalProperties: false };
  const validate = (value: unknown): { value: T } | { issues: { message: string }[] } => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      return { issues: [{ message: 'input must be an object' }] };
    }
    const record: Record<string, unknown> = { ...value };
    for (const key of Object.keys(record)) {
      if (!(key in properties)) {
        return { issues: [{ message: `unknown property ${JSON.stringify(key).slice(0, 64)}` }] };
      }
    }
    for (const key of required) {
      if (record[key] === undefined) {
        return { issues: [{ message: `missing property ${key}` }] };
      }
    }
    const path = record['path'];
    if (typeof path !== 'string') {
      return { issues: [{ message: 'path must be a string' }] };
    }
    const refined = refine({ ...record, path });
    return refined === undefined ? { issues: [{ message: 'invalid input' }] } : { value: refined };
  };
  return {
    '~standard': {
      version: 1,
      vendor: 'agent-tunnel',
      validate,
      jsonSchema: {
        input: () => json,
        output: () => json,
      },
    },
  };
}
