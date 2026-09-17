/**
 * Contract compilation, and the runtime half of it.
 *
 * `docs/testing.md`: "Compile the actual adapters against installed Files SDK,
 * Mastra, just-bash, and AI SDK declarations using a checked-in lockfile. Type
 * assertions, locally copied interface substitutes, suppressed type errors, and
 * tests that import only our own types cannot satisfy this gate."
 *
 * Two things do that work, and they are separate on purpose:
 *
 * * **Compilation** is `npm run typecheck`. Each adapter's *source* imports the
 *   upstream declarations with `import type` and is annotated with the upstream
 *   interface, so `tsc` checks the implementation against the installed
 *   package's own `.d.ts`. There is no `any`, no `as` onto an upstream type and
 *   no `@ts-expect-error` anywhere in `src/adapters/`.
 * * **Registration and behaviour** is this file, run by `npm run test:peers`.
 *   It loads the real packages, hands each adapter to the thing that consumes
 *   it — `new Files({ adapter })`, `new Workspace({ filesystem })`,
 *   `new Bash({ fs })`, `ai.uploadFile({ api })` — and drives supported
 *   operations through their public APIs against the loopback harness.
 *
 * It is **not** part of `npm test`, which runs offline with `node_modules`
 * deleted. And it is not evidence about a relay or a device: the socket is the
 * same loopback harness, so what it establishes is that these adapters satisfy
 * their frameworks, not that the endpoint behind them interoperates.
 */

import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { after, describe, it } from 'node:test';

import { Files, FilesError, type Adapter } from 'files-sdk';
import * as workspaceModule from '@mastra/core/workspace';
import { Workspace } from '@mastra/core/workspace';
import { Bash } from 'just-bash';
import type { IFileSystem, SecurityViolationType } from 'just-bash';
import { uploadFile } from 'ai';
import type { FilesV4 } from '@ai-sdk/provider';

import { createFilesAdapter, type FilesErrorConstructor } from '../../src/adapters/files-sdk.ts';
import { TunnelMastraFilesystem, type MastraErrorClasses } from '../../src/adapters/mastra.ts';
import {
  REQUIRED_DEFENSE_EXCLUSIONS,
  TunnelJustBashFilesystem,
} from '../../src/adapters/just-bash.ts';
import { createFilesApi, PROVIDER_KEY } from '../../src/adapters/ai-sdk.ts';
import { FilesystemError } from '../../src/errors.ts';
import type { RemoteFilesystem } from '../../src/filesystem.ts';
import { closeAll, waitFor, wire } from '../adapters/wiring.ts';
import type { FakeProvider } from '../harness/provider.ts';

after(closeAll);

/* ---------------------------------------------------------------------- *
 * Assignability, asserted rather than assumed
 * ---------------------------------------------------------------------- */

// The upstream class really does satisfy the constructor shape the Files
// adapter asks a consumer for. Without this, a signature change upstream would
// be caught only when a consumer tried to pass the class.
const filesErrorIsAccepted: FilesErrorConstructor = FilesError;

// The module namespace really does carry the nine error classes the Mastra
// adapter names, with the constructor signatures it calls them by.
const mastraErrorsAreAccepted: MastraErrorClasses = workspaceModule;

describe('the pinned packages are the pinned packages', () => {
  it('resolves the exact versions the adapters are written against', () => {
    // Read off disk rather than imported. Neither `files-sdk` nor `ai` exposes
    // `./package.json` through its `exports` map, and `files-sdk` has no CJS
    // main either, so `import()` and `require.resolve()` both refuse — worth
    // knowing when pinning them, and the reason this reads the installed tree.
    const versions = ['files-sdk', '@mastra/core', 'just-bash', 'ai', '@ai-sdk/provider'].map(
      (name) => {
        const manifest = JSON.parse(
          readFileSync(new URL(`../../node_modules/${name}/package.json`, import.meta.url), 'utf8'),
        ) as { version: string };
        return [name, manifest.version] as const;
      },
    );
    assert.deepEqual(Object.fromEntries(versions), {
      'files-sdk': '2.4.0',
      '@mastra/core': '1.65.0',
      'just-bash': '3.4.2',
      ai: '7.0.94',
      '@ai-sdk/provider': '4.0.11',
    });
  });

  it('accepts the upstream classes the adapters ask their consumers for', () => {
    assert.equal(filesErrorIsAccepted, FilesError);
    assert.equal(typeof mastraErrorsAreAccepted.StaleFileError, 'function');
  });
});

async function remoteOver(
  seed: Record<string, string | Uint8Array> = {},
  configure?: (provider: FakeProvider) => void,
): Promise<{ remote: RemoteFilesystem; wired: Awaited<ReturnType<typeof wire>> }> {
  const wired = await wire(seed, {}, configure ?? (() => {}));
  return { remote: wired.remote, wired };
}

/* ---------------------------------------------------------------------- *
 * Files SDK
 * ---------------------------------------------------------------------- */

describe('Files SDK: the real wrapper over the real adapter', () => {
  it('registers with new Files({ adapter }) and runs its supported methods', async () => {
    const { remote, wired } = await remoteOver({ 'notes.txt': 'hello world' });
    const adapter: Adapter = createFilesAdapter({ remote, FilesError });
    const files = new Files({ adapter, retries: 0 });

    assert.equal((await files.head('notes.txt')).size, 11);
    assert.equal(await files.exists('notes.txt'), true);
    assert.equal(await files.exists('missing.txt'), false);
    assert.equal(await (await files.download('notes.txt')).text(), 'hello world');

    await files.upload('out/a.txt', 'written');
    assert.equal(new TextDecoder().decode(wired.provider.read('/out/a.txt')), 'written');

    await files.copy('out/a.txt', 'out/b.txt');
    await files.move('out/b.txt', 'out/c.txt');
    assert.equal(wired.provider.has('/out/b.txt'), false);
    await files.delete('out/c.txt');

    const listed = await files.list();
    assert.ok(listed.items.some((item) => item.key === 'notes.txt'));
  });

  it('reports the capability snapshot the adapter advertises', async () => {
    const { remote } = await remoteOver();
    const files = new Files({ adapter: createFilesAdapter({ remote, FilesError }), retries: 0 });
    const capabilities = files.capabilities;
    assert.equal(capabilities.rangeRead, true);
    assert.equal(capabilities.delimiter, true);
    assert.equal(capabilities.metadata, false);
    assert.equal(capabilities.cacheControl, false);
    assert.equal(capabilities.serverSideCopy, false);
    assert.equal(capabilities.multipart, false);
    assert.deepEqual(capabilities.signedUrl, { supported: false });
    // Every conditional primitive is unsupported because the adapter omits the
    // `conditional` block entirely, so upstream fails those calls before I/O.
    assert.equal(capabilities.conditional.create, false);
    assert.equal(capabilities.conditional.replace, false);
    assert.equal(capabilities.conditional.exactRead, false);
    assert.equal(capabilities.conditional.delete, false);
  });

  it('raises a real FilesError, which is what makes the retry gate work at all', async () => {
    const { remote } = await remoteOver();
    const files = new Files({ adapter: createFilesAdapter({ remote, FilesError }), retries: 0 });
    await assert.rejects(
      async () => files.head('missing.txt'),
      (error: unknown) => {
        // `FilesError.wrap` returns its cause unchanged only when it is an
        // instance of the class the wrapper itself imported. A structurally
        // similar object would become a fresh `Provider` error with `permanent`
        // unset — that is, a retryable one.
        assert.ok(error instanceof FilesError);
        assert.equal(error.code, 'NotFound');
        return true;
      },
    );
  });

  it('dispatches an ambiguous mutation exactly once with retries enabled', async () => {
    const { remote, wired } = await remoteOver({}, (provider) => {
      provider.swallow.add('Twrite');
    });
    // Five retries, deliberately: "the adapter must also prevent retry if the
    // application enables SDK retries", and an example that sets zero proves
    // nothing about an application that does not.
    const files = new Files({ adapter: createFilesAdapter({ remote, FilesError }), retries: 5 });
    const pending = files.upload('fresh.txt', 'abc');
    await waitFor(() => wired.connection.received.some((message) => message.kind === 'Twrite'));
    wired.connection.close(1011, 'synthetic');

    await assert.rejects(pending, (error: unknown) => {
      assert.ok(error instanceof FilesError);
      assert.equal(error.code, 'Provider');
      assert.equal(error.permanent, true);
      // Never set for an ambiguous outcome: upstream it means a conditional
      // mutation committed.
      assert.equal(error.applied, false);
      assert.ok(error.cause instanceof FilesystemError);
      assert.equal((error.cause as FilesystemError).outcome, 'unknown');
      return true;
    });

    // The thing this test exists for: one `Twrite` on the wire, not six.
    assert.equal(
      wired.connection.received.filter((message) => message.kind === 'Twrite').length,
      1,
      'an ambiguous mutation must never be replayed',
    );
  });

  it('fails a conditional upload before any provider call', async () => {
    const { remote, wired } = await remoteOver();
    const files = new Files({ adapter: createFilesAdapter({ remote, FilesError }), retries: 0 });
    const before = wired.connection.received.length;
    await assert.rejects(async () => files.upload('a.txt', 'x', { condition: { type: 'create' } }));
    assert.equal(wired.connection.received.length, before, 'nothing reached the socket');
  });
});

/* ---------------------------------------------------------------------- *
 * Mastra
 * ---------------------------------------------------------------------- */

describe('Mastra: a real Workspace over the real filesystem provider', () => {
  it('mounts in new Workspace({ filesystem }) and runs its operations', async () => {
    const { remote, wired } = await remoteOver({ 'notes.txt': 'hello' });
    const filesystem = new TunnelMastraFilesystem({ remote, errors: workspaceModule });
    const workspace = new Workspace({ filesystem });
    await workspace.init();

    assert.equal((await workspace.filesystem.readFile('/notes.txt', { encoding: 'utf8' })), 'hello');
    await workspace.filesystem.writeFile('/code/app.py', 'print("hello")');
    assert.equal(new TextDecoder().decode(wired.provider.read('/code/app.py')), 'print("hello")');
    assert.equal(await workspace.filesystem.exists('/code/app.py'), true);
    assert.equal((await workspace.filesystem.stat('/code/app.py')).type, 'file');
    assert.ok((await workspace.filesystem.readdir('/')).some((entry) => entry.name === 'code'));

    await workspace.destroy();
    // Destroying the workspace released the wrapper, not the borrowed client.
    assert.equal(remote.state, 'ready');
  });

  it('implies no host command-execution sandbox', async () => {
    const { remote } = await remoteOver();
    const workspace = new Workspace({
      filesystem: new TunnelMastraFilesystem({ remote, errors: workspaceModule }),
    });
    await workspace.init();
    // "filesystem access must not imply a host command-execution sandbox".
    assert.equal(workspace.sandbox, undefined);
    await workspace.destroy();
  });

  it('throws the real error classes, which a Mastra tool branches on', async () => {
    const { remote } = await remoteOver({ 'a.txt': 'x' });
    const filesystem = new TunnelMastraFilesystem({ remote, errors: workspaceModule });
    await assert.rejects(
      async () => filesystem.readFile('/missing.txt'),
      (error: unknown) => error instanceof workspaceModule.FileNotFoundError,
    );
    await assert.rejects(
      async () => filesystem.writeFile('/a.txt', 'y', { overwrite: false }),
      (error: unknown) => error instanceof workspaceModule.FileExistsError,
    );
  });

  it('throws the real StaleFileError under the check-before-write profile', async () => {
    const { remote } = await remoteOver({ 'a.txt': 'x' });
    const filesystem = new TunnelMastraFilesystem({
      remote,
      errors: workspaceModule,
      mtimePolicy: 'check-before-write',
    });
    await assert.rejects(
      async () => filesystem.writeFile('/a.txt', 'y', { expectedMtime: new Date(1) }),
      (error: unknown) => {
        assert.ok(error instanceof workspaceModule.StaleFileError);
        assert.equal(error.expectedMtime.getTime(), 1);
        return true;
      },
    );
  });
});

/* ---------------------------------------------------------------------- *
 * just-bash
 * ---------------------------------------------------------------------- */

const excludeViolationTypes: SecurityViolationType[] = [...REQUIRED_DEFENSE_EXCLUSIONS];

describe('just-bash: a real Bash over the real IFileSystem', () => {
  it('runs command transcripts with host, network and code execution off', async () => {
    const { remote } = await remoteOver({ 'notes.txt': 'hello\nworld\n', 'dir/a.txt': 'x' });
    const fs: IFileSystem = new TunnelJustBashFilesystem({ remote });
    // Network, python and javascript are all off by default and are not
    // enabled here: "Disable optional network, JS/Python execution, and any
    // host-exec custom commands in supported default examples."
    //
    // `setTimeout` is excluded from the defense-in-depth box because the shared
    // client arms a timer for every request deadline and just-bash blocks the
    // global for the duration of a script. Without it the first `cat` fails
    // before a byte reaches the socket. See `REQUIRED_DEFENSE_EXCLUSIONS`.
    const bash = new Bash({ fs, cwd: '/', defenseInDepth: { excludeViolationTypes } });

    const cat = await bash.exec('cat /notes.txt');
    assert.equal(cat.exitCode, 0);
    assert.equal(cat.stdout, 'hello\nworld\n');

    const wc = await bash.exec('cat /notes.txt | wc -l');
    assert.equal(wc.stdout.trim(), '2');

    const ls = await bash.exec('ls /');
    assert.ok(ls.stdout.includes('notes.txt'));
    assert.ok(ls.stdout.includes('dir'));

    const write = await bash.exec('echo written > /out.txt');
    assert.equal(write.exitCode, 0);
    assert.equal((await bash.exec('cat /out.txt')).stdout, 'written\n');

    const copy = await bash.exec('cp /notes.txt /copy.txt && mv /copy.txt /moved.txt && ls /moved.txt');
    assert.equal(copy.exitCode, 0);
  });

  it('round-trips binary bytes through the shell without a text detour', async () => {
    const binary = Uint8Array.from({ length: 256 }, (_value, index) => index);
    const { remote } = await remoteOver({ 'blob.bin': binary });
    const bash = new Bash({
      fs: new TunnelJustBashFilesystem({ remote }),
      cwd: '/',
      defenseInDepth: { excludeViolationTypes },
    });
    const sum = await bash.exec('cat /blob.bin | wc -c');
    assert.equal(sum.stdout.trim(), '256');
  });

  it('fails an append with a documented filesystem error rather than emulating one', async () => {
    const { remote, wired } = await remoteOver({ 'notes.txt': 'hello\n' });
    const bash = new Bash({
      fs: new TunnelJustBashFilesystem({ remote }),
      cwd: '/',
      defenseInDepth: { excludeViolationTypes },
    });
    // Shell `>>` is `appendFile`, and this endpoint advertises no atomic
    // append. just-bash 3.4.2 lets a redirect-target failure **reject** out of
    // `exec` rather than turning it into a shell exit status, so a consumer
    // must catch it; the file is untouched either way.
    await assert.rejects(
      async () => bash.exec('echo more >> /notes.txt'),
      (error: unknown) => {
        assert.ok(error instanceof Error);
        assert.match(error.message, /ENOTSUP \(appendFile\)/u);
        return true;
      },
    );
    assert.equal(new TextDecoder().decode(wired.provider.read('/notes.txt')), 'hello\n');
  });

  it('keeps the structured outcome a nonzero exit code throws away', async () => {
    const { remote, wired } = await remoteOver({}, (provider) => {
      provider.swallow.add('Twrite');
    });
    const fs = new TunnelJustBashFilesystem({ remote });
    const bash = new Bash({ fs, cwd: '/', defenseInDepth: { excludeViolationTypes } });
    const pending = bash.exec('echo abc > /fresh.txt');
    await waitFor(() => wired.connection.received.some((message) => message.kind === 'Twrite'));
    wired.connection.close(1011, 'synthetic');

    // **There is no exit status.** A redirect-target failure rejects out of
    // `exec` in just-bash 3.4.2, exactly as `>>` does, so a tool wrapper that
    // only reads `ExecResult` never runs at all — and one that catches and
    // synthesises a status has invented the very thing that carries nothing.
    await assert.rejects(pending, (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.match(error.message, /SESSION_LOST \(writeFile\)/u);
      return true;
    });

    // What a wrapper must therefore report, and must not infer "safe to retry" without.
    const drained = fs.drainOperationFailures();
    assert.equal(drained.dropped, 0);
    assert.equal(drained.entries.length, 1);
    assert.equal(drained.entries[0]?.outcome, 'unknown');
  });
});

/* ---------------------------------------------------------------------- *
 * AI SDK
 * ---------------------------------------------------------------------- */

describe("AI SDK: the real ai.uploadFile over the real FilesV4", () => {
  it('uploads through the pinned helper and calls the provider exactly once', async () => {
    const { remote, wired } = await remoteOver({ 'uploads/.keep': '' });
    const files = createFilesApi({ remote, uploadDirectory: '/uploads' });
    const api: FilesV4 = files;
    let dispatched = 0;
    const counted: FilesV4 = {
      ...api,
      specificationVersion: api.specificationVersion,
      provider: api.provider,
      uploadFile: async (call) => {
        dispatched += 1;
        return await api.uploadFile(call);
      },
    };

    const result = await uploadFile({
      api: counted,
      data: new TextEncoder().encode('payload'),
      mediaType: 'text/plain',
      filename: 'notes.txt',
    });
    // "The inspected `ai.uploadFile` helper calls `FilesV4.uploadFile` once and
    // rethrows failures; it has no `maxRetries` option to disable."
    assert.equal(dispatched, 1);
    const id = result.providerReference[PROVIDER_KEY];
    assert.ok(typeof id === 'string');
    assert.equal(wired.provider.has(`/uploads/${id as string}`), true);
  });

  it('rethrows an ambiguous upload without a second dispatch', async () => {
    const { remote, wired } = await remoteOver({ 'uploads/.keep': '' }, (provider) => {
      provider.swallow.add('Twrite');
    });
    const files = createFilesApi({ remote, uploadDirectory: '/uploads' });
    const pending = uploadFile({
      api: files,
      data: new TextEncoder().encode('payload'),
      mediaType: 'text/plain',
    });
    await waitFor(() => wired.connection.received.some((message) => message.kind === 'Twrite'));
    wired.connection.close(1011, 'synthetic');

    await assert.rejects(pending, (error: unknown) => {
      assert.ok(error instanceof FilesystemError);
      assert.equal(error.outcome, 'unknown');
      return true;
    });
    assert.equal(
      wired.connection.received.filter((message) => message.kind === 'Twrite').length,
      1,
    );
    assert.equal(files.incompleteUploads().length, 1);
  });

  it('runs the optional methods on the provider instance itself', async () => {
    const { remote } = await remoteOver({ 'uploads/.keep': '' });
    const files = createFilesApi({ remote, uploadDirectory: '/uploads' });
    // A **string** handed to `ai.uploadFile` becomes `{ type: 'data', data }`,
    // which `FilesV4` defines as "raw bytes or a **base64-encoded** string" —
    // not inline text. Plain text goes through `{ type: 'text', text }` on the
    // instance, or as bytes here. Recorded because it is an easy way to upload
    // a file whose content is not what the caller wrote.
    const uploaded = await uploadFile({
      api: files,
      data: new TextEncoder().encode('hello'),
      mediaType: 'text/plain',
    });
    // "Invoke optional metadata/download/delete methods on the FilesV4 instance
    // itself": `ai` has no helper for them.
    const metadata = await files.getFileMetadata?.({ file: uploaded.providerReference });
    assert.equal(metadata?.byteSize, 5);
    const download = await files.downloadFile?.({ file: uploaded.providerReference });
    assert.ok(download?.content instanceof ReadableStream);
    await download?.content.cancel();
    const deleted = await files.deleteFile?.({ file: uploaded.providerReference });
    assert.equal(deleted?.deleted, true);
  });
});
