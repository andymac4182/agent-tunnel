/**
 * The Mastra adapter's workspace view, its two timestamp policies, and the
 * outcomes its error classes have no word for.
 */

import { strict as assert } from 'node:assert';
import { after, describe, it } from 'node:test';

import { TunnelMastraFilesystem } from '../../src/adapters/mastra.ts';
import { FilesystemError } from '../../src/errors.ts';
import { descriptorFixture } from '../harness/descriptor.ts';
import { closeAll, standInMastraErrors, waitFor, wire, type Wired } from './wiring.ts';
import type { FakeProvider } from '../harness/provider.ts';

after(closeAll);

async function mount(
  seed: Record<string, string | Uint8Array> = {},
  overrides = {},
  mtimePolicy: 'reject' | 'check-before-write' = 'reject',
  configure?: (provider: FakeProvider) => void,
): Promise<{ fs: TunnelMastraFilesystem; wired: Wired }> {
  const wired = await wire(seed, overrides, configure ?? (() => {}));
  const fs = new TunnelMastraFilesystem({
    remote: wired.remote,
    errors: standInMastraErrors,
    mtimePolicy,
  });
  await fs.init();
  return { fs, wired };
}

const raised = async (run: () => Promise<unknown>): Promise<Error> => {
  try {
    await run();
  } catch (error) {
    assert.ok(error instanceof Error);
    return error;
  }
  throw new Error('expected a rejection');
};

const codeOf = (error: Error): string => (error as { code?: string }).code ?? '';

describe('identity, lifecycle and what the provider tells an agent', () => {
  it('reports an id, a provider and a read-only flag derived from the grant', async () => {
    const { fs } = await mount();
    assert.equal(fs.provider, 'agent-tunnel');
    assert.equal(fs.name, 'TunnelMastraFilesystem');
    assert.match(fs.id, /^agent-tunnel:device-123\/workspace$/u);
    assert.equal(fs.readOnly, false);
    assert.equal(fs.status, 'ready');
  });

  it('destroy releases the wrapper and never the borrowed connection', async () => {
    const { fs, wired } = await mount({ 'a.txt': 'x' });
    await fs.destroy();
    assert.equal(fs.status, 'destroyed');
    // Another borrower may still hold the same client. Closing it here would be
    // one adapter ending another adapter's session.
    assert.equal(wired.remote.state, 'ready');
    assert.deepEqual(await wired.remote.readFile('/a.txt'), new TextEncoder().encode('x'));
  });

  it('declares the created-time fallback and the timestamp policy it is running', async () => {
    const { fs } = await mount();
    const info = fs.getInfo();
    assert.equal(info.metadata?.createdAtSource, 'mtime-fallback');
    assert.equal(info.metadata?.mtimePolicy, 'reject');
    assert.equal(info.metadata?.conditionalWrites, false);
    assert.match(fs.getInstructions(), /not a creation time/u);
    assert.match(fs.getInstructions(), /appendFile is unsupported/u);
  });

  it('has no disk path to resolve, and says so rather than inventing one', async () => {
    const { fs } = await mount();
    // "Returns `undefined` if the filesystem doesn't support disk-path
    // resolution (e.g., remote/in-memory filesystems)." There is no host path
    // anywhere on this wire for one to be built from.
    assert.equal(fs.resolveAbsolutePath(), undefined);
  });
});

describe('the eleven operations over a real socket', () => {
  it('returns a Buffer by default and decodes a requested encoding', async () => {
    const { fs } = await mount({ 'notes.txt': 'hello' });
    const buffer = await fs.readFile('/notes.txt');
    assert.ok(Buffer.isBuffer(buffer));
    assert.equal(buffer.toString('utf8'), 'hello');
    assert.equal(await fs.readFile('/notes.txt', { encoding: 'utf8' }), 'hello');
    assert.equal(await fs.readFile('/notes.txt', { encoding: 'base64' }), 'aGVsbG8=');
  });

  it('creates parents by default and not when recursive is false', async () => {
    const { fs, wired } = await mount();
    await fs.writeFile('/deep/nested/a.txt', 'x');
    assert.equal(wired.provider.has('/deep/nested/a.txt'), true);
    const error = await raised(async () => fs.writeFile('/other/b.txt', 'x', { recursive: false }));
    assert.ok(error instanceof Error);
    assert.equal(wired.provider.has('/other/b.txt'), false);
  });

  it('honours overwrite:false with exclusive creation and no preliminary stat', async () => {
    const { fs, wired } = await mount({ 'a.txt': 'old' });
    const error = await raised(async () => fs.writeFile('/a.txt', 'new', { overwrite: false }));
    assert.equal(error.name, 'FileExistsError');
    assert.equal(new TextDecoder().decode(wired.provider.read('/a.txt')), 'old');
    // The exclusivity is `Tlcreate`, which this profile makes exclusive
    // whatever the flag word said — never an exists-then-create race.
    assert.equal(
      wired.connection.received.some((message) => message.kind === 'Tgetattr'),
      false,
    );
  });

  it('appendFile is an explicit unsupported operation, never an emulated append', async () => {
    const { fs, wired } = await mount({ 'a.txt': 'old' });
    const error = await raised(async () => fs.appendFile('/a.txt', ' more'));
    assert.equal(codeOf(error), 'TUNNEL_ENOTSUP');
    // Not a no-op that reports success, and not a stat followed by a write.
    assert.equal(new TextDecoder().decode(wired.provider.read('/a.txt')), 'old');
    assert.equal(
      wired.connection.received.some((message) => message.kind === 'Twrite'),
      false,
    );
  });

  it('deletes a file, refuses a directory, and removes a directory through rmdir', async () => {
    const { fs, wired } = await mount({ 'dir/a.txt': 'x' });
    const conflict = await raised(async () => fs.deleteFile('/dir'));
    assert.equal(conflict.name, 'IsDirectoryError');
    await fs.deleteFile('/dir/a.txt');
    assert.equal(wired.provider.has('/dir/a.txt'), false);
    await fs.rmdir('/dir');
    assert.equal(wired.provider.has('/dir'), false);
  });

  it('moves with a native rename and refuses move-without-overwrite', async () => {
    const { fs, wired } = await mount({ 'a.txt': 'payload' });
    const refused = await raised(async () => fs.moveFile('/a.txt', '/b.txt', { overwrite: false }));
    assert.equal(codeOf(refused), 'TUNNEL_ENOTSUP');
    // Refused **before** the rename: an existence check here would be the race
    // the contract forbids, and doing it anyway would leave the file moved.
    assert.equal(wired.provider.has('/a.txt'), true);
    await fs.moveFile('/a.txt', '/b.txt');
    assert.equal(new TextDecoder().decode(wired.provider.read('/b.txt')), 'payload');
  });

  it('copies a regular file and refuses a directory rather than half-copying one', async () => {
    const { fs, wired } = await mount({ 'dir/a.txt': 'x' });
    await fs.copyFile('/dir/a.txt', '/out/a.txt');
    assert.equal(new TextDecoder().decode(wired.provider.read('/out/a.txt')), 'x');
    const error = await raised(async () => fs.copyFile('/dir', '/dir2', { recursive: true }));
    assert.equal(codeOf(error), 'TUNNEL_ENOTSUP');
  });

  it('lists immediate children, recurses when asked, and filters by extension', async () => {
    const { fs } = await mount({ 'a.ts': '1', 'b.md': '2', 'sub/c.ts': '3' });
    const flat = await fs.readdir('/');
    assert.deepEqual(
      flat.map((entry) => entry.name).sort(),
      ['a.ts', 'b.md', 'sub'],
    );
    const deep = await fs.readdir('/', { recursive: true, extension: '.ts' });
    assert.deepEqual(deep.map((entry) => entry.name).sort(), ['a.ts', 'c.ts']);
  });

  it('fails a listing on the traversal budget instead of truncating it', async () => {
    const { fs } = await mount(
      { 'a.txt': '1', 'b.txt': '2', 'c.txt': '3' },
      { limits: { ...descriptorFixture().limits, maxTraversalEntries: 2 } },
    );
    const error = await raised(async () => fs.readdir('/'));
    assert.match(error.message, /EFBIG/u);
  });

  it('stat gives a numeric size and a createdAt that is the documented fallback', async () => {
    const { fs } = await mount({ 'a.txt': 'hello' });
    const stat = await fs.stat('/a.txt');
    assert.equal(stat.type, 'file');
    assert.equal(stat.size, 5);
    assert.equal(stat.path, '/a.txt');
    assert.equal(stat.name, 'a.txt');
    assert.ok(stat.modifiedAt instanceof Date);
    // `birthTime` is absent from the fixture's features, so `createdAt` is the
    // modification time — a compatibility convention, declared in `getInfo`.
    assert.equal(stat.createdAt.getTime(), stat.modifiedAt.getTime());
  });

  it('exists is false only for a confirmed absence', async () => {
    const { fs } = await mount({ 'a.txt': 'x' });
    assert.equal(await fs.exists('/a.txt'), true);
    assert.equal(await fs.exists('/missing.txt'), false);
    // A path this namespace refuses is not an absent file.
    await assert.rejects(async () => fs.exists('/../escape'));
  });
});

describe('the two timestamp policies', () => {
  it("'reject' refuses the condition before any mutation, and that is the default", async () => {
    const { fs, wired } = await mount({ 'a.txt': 'old' });
    assert.equal(fs.mtimePolicy, 'reject');
    const error = await raised(async () =>
      fs.writeFile('/a.txt', 'new', { expectedMtime: new Date(1) }),
    );
    assert.equal(codeOf(error), 'TUNNEL_ENOTSUP');
    // Nothing was created, truncated or written. Mastra's read tracking
    // supplies this condition internally, so this default really does not
    // support an ordinary read-then-edit tool on a writable mount.
    assert.equal(new TextDecoder().decode(wired.provider.read('/a.txt')), 'old');
    assert.equal(
      wired.connection.received.some((message) => message.kind === 'Twrite'),
      false,
    );
  });

  it("'check-before-write' matches the stat's own millisecond and proceeds", async () => {
    const { fs, wired } = await mount({ 'a.txt': 'old' }, {}, 'check-before-write');
    const stat = await fs.stat('/a.txt');
    await fs.writeFile('/a.txt', 'new', { expectedMtime: stat.modifiedAt });
    assert.equal(new TextDecoder().decode(wired.provider.read('/a.txt')), 'new');
  });

  it("'check-before-write' throws the real StaleFileError on a mismatch", async () => {
    const { fs, wired } = await mount({ 'a.txt': 'old' }, {}, 'check-before-write');
    const error = await raised(async () =>
      fs.writeFile('/a.txt', 'new', { expectedMtime: new Date(1) }),
    );
    assert.equal(error.name, 'StaleFileError');
    assert.equal(new TextDecoder().decode(wired.provider.read('/a.txt')), 'old');
    assert.equal(
      wired.connection.received.some((message) => message.kind === 'Twrite'),
      false,
    );
  });

  it("'check-before-write' proceeds for a missing file, as the pinned LocalFilesystem does", async () => {
    const { fs, wired } = await mount({}, {}, 'check-before-write');
    await fs.writeFile('/fresh.txt', 'new', { expectedMtime: new Date(1) });
    assert.equal(new TextDecoder().decode(wired.provider.read('/fresh.txt')), 'new');
  });

  it("'check-before-write' preserves a stat failure that is not an absence", async () => {
    const { fs } = await mount({ 'a.txt': 'x' }, {}, 'check-before-write');
    // A refused path fails at validation, which is not a stale file and must
    // not be reported as one.
    const error = await raised(async () =>
      fs.writeFile('/CON', 'new', { expectedMtime: new Date(1) }),
    );
    assert.notEqual(error.name, 'StaleFileError');
    assert.equal(codeOf(error), 'TUNNEL_PATH_REFUSED');
  });

  it('neither policy changes what the endpoint advertises', async () => {
    const { fs } = await mount({}, {}, 'check-before-write');
    assert.equal(fs.getInfo().metadata?.conditionalWrites, false);
    assert.equal(fs.getInfo().metadata?.mtimePolicy, 'check-before-write');
  });
});

describe('outcomes, and what Mastra can and cannot say about them', () => {
  it('an unknown mutation is never one of Mastra’s semantic errors', async () => {
    const { fs, wired } = await mount({}, {}, 'reject', (provider) => {
      provider.swallow.add('Twrite');
    });
    const pending = fs.writeFile('/fresh.txt', 'abc');
    await waitFor(() => wired.connection.received.some((message) => message.kind === 'Twrite'));
    wired.connection.close(1011, 'synthetic');
    const error = await raised(async () => pending);

    // `FileNotFoundError` would say the file is absent; `FileExistsError` would
    // say the write was refused. Both read as "nothing happened", and after an
    // `unknown` nobody knows that.
    assert.equal(error.name, 'FilesystemError');
    assert.equal(codeOf(error), 'TUNNEL_UNKNOWN');
    const cause = (error as { cause?: unknown }).cause;
    assert.ok(cause instanceof FilesystemError);
    assert.equal(cause.outcome, 'unknown');
  });

  it('a partial composite is TUNNEL_PARTIAL, distinguished from unknown only by its code', async () => {
    // A recursive `mkdir` that made `/a` and was then refused `/a/b`. The
    // export is not as it was, so `not_started` would be false and
    // `DirectoryNotFoundError` would be read as "nothing happened".
    const { fs, wired } = await mount({}, {}, 'reject', (provider) => {
      provider.failAfter.set('Tmkdir', { after: 1, ecode: 13 });
    });
    const error = await raised(async () => fs.mkdir('/a/b', { recursive: true }));
    assert.equal(wired.provider.has('/a'), true, 'the first directory was made');
    assert.equal(codeOf(error), 'TUNNEL_PARTIAL');
    const cause = (error as { cause?: unknown }).cause;
    assert.ok(cause instanceof FilesystemError);
    assert.equal(cause.outcome, 'partial');
  });

  it('carries the virtual path the caller supplied and nothing host-derived', async () => {
    const { fs } = await mount({});
    const error = await raised(async () => fs.readFile('/missing.txt'));
    assert.equal(error.name, 'FileNotFoundError');
    // Mastra's own error class takes a path and renders it. It is the virtual
    // path the caller itself wrote; there is no host path anywhere on the wire
    // for this client to have learned.
    assert.equal((error as { path?: string }).path, '/missing.txt');
  });
});
