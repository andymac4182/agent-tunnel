/**
 * The just-bash adapter's `IFileSystem`, and the structured side channel that
 * exists because a shell's own vocabulary has nowhere to put an outcome.
 */

import { strict as assert } from 'node:assert';
import { after, describe, it } from 'node:test';

import {
  MAX_OPERATION_FAILURES,
  REQUIRED_DEFENSE_EXCLUSIONS,
  TunnelJustBashFilesystem,
} from '../../src/adapters/just-bash.ts';
import { FilesystemError } from '../../src/errors.ts';
import { closeAll, waitFor, wire, type Wired } from './wiring.ts';
import type { FakeProvider } from '../harness/provider.ts';

after(closeAll);

async function mount(
  seed: Record<string, string | Uint8Array> = {},
  overrides = {},
  configure?: (provider: FakeProvider) => void,
): Promise<{ fs: TunnelJustBashFilesystem; wired: Wired }> {
  const wired = await wire(seed, overrides, configure ?? (() => {}));
  return { fs: new TunnelJustBashFilesystem({ remote: wired.remote }), wired };
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

describe('the methods a shell calls', () => {
  it('reads text and bytes, and a text read never goes through a byte round trip', async () => {
    const binary = new Uint8Array([0, 1, 2, 250, 255]);
    const { fs } = await mount({ 'notes.txt': 'hello', 'blob.bin': binary });
    assert.equal(await fs.readFile('/notes.txt'), 'hello');
    assert.equal(await fs.readFile('/notes.txt', 'base64'), 'aGVsbG8=');
    assert.deepEqual(await fs.readFileBuffer('/blob.bin'), binary);
    // A latin1 read is the bytes, one character each: binary fidelity through
    // the encoding just-bash's pipelines use for bytes.
    assert.equal((await fs.readFile('/blob.bin', 'latin1')).length, 5);
  });

  it('writes, copies, moves, removes and lists', async () => {
    const { fs, wired } = await mount({ 'a.txt': 'payload' });
    await fs.writeFile('/b.txt', 'written');
    assert.equal(new TextDecoder().decode(wired.provider.read('/b.txt')), 'written');
    await fs.cp('/a.txt', '/c.txt');
    assert.equal(await fs.readFile('/c.txt'), 'payload');
    await fs.mv('/c.txt', '/d.txt');
    assert.equal(wired.provider.has('/c.txt'), false);
    await fs.mkdir('/dir');
    assert.deepEqual((await fs.readdir('/')).sort(), ['a.txt', 'b.txt', 'd.txt', 'dir']);
    await fs.rm('/d.txt');
    assert.equal(wired.provider.has('/d.txt'), false);
  });

  it('reports entry types without a stat per name', async () => {
    const { fs } = await mount({ 'a.txt': 'x', 'dir/b.txt': 'y' });
    const entries = await fs.readdirWithFileTypes('/');
    assert.deepEqual(
      entries.map((entry) => [entry.name, entry.isFile, entry.isDirectory]).sort(),
      [
        ['a.txt', true, false],
        ['dir', false, true],
      ],
    );
  });

  it('stats without disclosing a host inode or identity', async () => {
    const { fs } = await mount({ 'a.txt': 'hello' });
    const stat = await fs.stat('/a.txt');
    assert.equal(stat.isFile, true);
    assert.equal(stat.isDirectory, false);
    assert.equal(stat.size, 5);
    assert.ok(stat.mtime instanceof Date);
    // "File identity/metadata must not leak host inode, UID, or directory
    // details." The optional fields are absent rather than filled with a qid.
    assert.equal(stat.dev, undefined);
    assert.equal(stat.ino, undefined);
    assert.equal(stat.identity, undefined);
  });

  it('lstat is stat, which is honest while symlinks are absent', async () => {
    const { fs } = await mount({ 'a.txt': 'x' });
    assert.deepEqual(await fs.lstat('/a.txt'), await fs.stat('/a.txt'));
  });

  it('exists is false only for a confirmed absence', async () => {
    const { fs } = await mount({ 'a.txt': 'x' });
    assert.equal(await fs.exists('/a.txt'), true);
    assert.equal(await fs.exists('/missing'), false);
    await assert.rejects(async () => fs.exists('/../escape'));
  });
});

describe('the synchronous members, which may not touch the network', () => {
  it('resolvePath clamps .. at the root, lexically, with no round trip', async () => {
    const { fs, wired } = await mount();
    const before = wired.connection.received.length;
    assert.equal(fs.resolvePath('/a/b', 'c.txt'), '/a/b/c.txt');
    assert.equal(fs.resolvePath('/a/b', '../c.txt'), '/a/c.txt');
    // just-bash's own contract: `..` above the root clamps rather than
    // escaping. It is **not** confinement — the shared client refuses any `..`
    // it is handed afterwards, and the device enforces confinement regardless.
    assert.equal(fs.resolvePath('/', '../../../etc/passwd'), '/etc/passwd');
    assert.equal(fs.resolvePath('/a', '/absolute/x'), '/absolute/x');
    assert.equal(fs.resolvePath('/a', './b/./c'), '/a/b/c');
    assert.equal(wired.connection.received.length, before, 'no request was sent');
  });

  it('getAllPaths is the upstream-permitted empty array', async () => {
    const { fs, wired } = await mount({ 'a.txt': 'x' });
    const before = wired.connection.received.length;
    // Synchronous, and this filesystem is remote. The alternative would be a
    // synchronous network call, so glob discovery that depends on this method
    // finds nothing; globs resolved through `readdir` work.
    assert.deepEqual(fs.getAllPaths(), []);
    assert.equal(wired.connection.received.length, before);
  });
});

describe('what this view cannot do, said explicitly', () => {
  it('refuses appendFile rather than emulating an append', async () => {
    const { fs, wired } = await mount({ 'a.txt': 'old' });
    const error = await raised(async () => fs.appendFile('/a.txt', ' more'));
    assert.equal(error.name, 'TunnelFilesystemError');
    assert.match(error.message, /^ENOTSUP \(appendFile\)$/u);
    // Shell `>>` therefore fails with a documented filesystem error. It is not
    // a stat followed by a positioned write, and not a read-modify-write.
    assert.equal(new TextDecoder().decode(wired.provider.read('/a.txt')), 'old');
    assert.equal(
      wired.connection.received.some((message) => message.kind === 'Twrite'),
      false,
    );
  });

  it('refuses a hard link, which this profile does not advertise', async () => {
    const { fs } = await mount({ 'a.txt': 'x' });
    const error = await raised(async () => fs.link('/a.txt', '/b.txt'));
    assert.match(error.message, /^ENOTSUP \(link\)$/u);
  });

  it('refuses a symlink and a readlink while the feature is absent', async () => {
    const { fs } = await mount({ 'a.txt': 'x' });
    assert.match((await raised(async () => fs.symlink('/a.txt', '/l'))).message, /ENOTSUP/u);
    assert.match((await raised(async () => fs.readlink('/l'))).message, /ENOTSUP/u);
  });

  it('refuses a recursive directory copy rather than half-copying a tree', async () => {
    const { fs } = await mount({ 'dir/a.txt': 'x' });
    const error = await raised(async () => fs.cp('/dir', '/dir2', { recursive: true }));
    assert.match(error.message, /^ENOTSUP \(cp\)$/u);
  });

  it('names the one defense-in-depth exclusion a remote filesystem needs', () => {
    // just-bash 3.4.2 blocks `globalThis.setTimeout` for the duration of a
    // script, and the shared client arms a timer for every request deadline —
    // so without this exclusion the first `cat` fails before a byte is sent.
    // `test/peers/` proves that one is enough and that nothing else is needed.
    assert.deepEqual([...REQUIRED_DEFENSE_EXCLUSIONS], ['setTimeout']);
  });

  it('carries no path or content in the message a shell would print', async () => {
    const { fs } = await mount();
    const error = await raised(async () => fs.readFile('/very-secret-name.txt'));
    assert.equal(error.message.includes('very-secret-name'), false, error.message);
    assert.match(error.message, /^ENOENT \(T?walk\)$/u);
  });
});

describe('drainOperationFailures: the outcome a shell cannot carry', () => {
  it('records an unknown mutation, which the thrown Error alone would lose', async () => {
    const { fs, wired } = await mount({}, {}, (provider) => {
      provider.swallow.add('Twrite');
    });
    const pending = fs.writeFile('/fresh.txt', 'abc');
    await waitFor(() => wired.connection.received.some((message) => message.kind === 'Twrite'));
    wired.connection.close(1011, 'synthetic');
    const error = await raised(async () => pending);

    // What a shell would see: a message, and then an exit status that keeps
    // none of it. An agent reading a nonzero exit code as "nothing happened"
    // would retry a write that may have landed.
    assert.equal(error.name, 'TunnelFilesystemError');
    const cause = (error as { cause?: unknown }).cause;
    assert.ok(cause instanceof FilesystemError);
    assert.equal(cause.outcome, 'unknown');

    // What the side channel keeps.
    const drained = fs.drainOperationFailures();
    assert.equal(drained.dropped, 0);
    assert.equal(drained.entries.length, 1);
    const entry = drained.entries[0];
    assert.ok(entry !== undefined);
    assert.equal(entry.operation, 'writeFile');
    assert.equal(entry.outcome, 'unknown');
    assert.equal(entry.path, '/fresh.txt');

    // Draining is taking: a second execution does not re-report the first's.
    assert.deepEqual(fs.drainOperationFailures(), { entries: [], dropped: 0 });
  });

  it('records nothing for a failure that provably did not apply', async () => {
    const { fs } = await mount();
    await raised(async () => fs.readFile('/missing.txt'));
    await raised(async () => fs.appendFile('/a.txt', 'x'));
    // `not_started` is not an ambiguous mutation and does not belong in a
    // channel whose whole purpose is the ambiguous ones.
    assert.deepEqual(fs.drainOperationFailures(), { entries: [], dropped: 0 });
  });

  it('bounds the scope and reports the overflow explicitly rather than forgetting it', async () => {
    // The default bound is 64 — and so is the consumer's in-flight tag quota,
    // so 65 ambiguous mutations at once is not something one session can do.
    // The bound itself is what is under test, so it is lowered; that the
    // default is the documented 64 is asserted separately below.
    const wired = await wire({}, {}, (provider) => {
      provider.swallow.add('Twrite');
    });
    const fs = new TunnelJustBashFilesystem({ remote: wired.remote, maxOperationFailures: 3 });
    const pendings: Array<Promise<unknown>> = [];
    for (let index = 0; index < 6; index += 1) {
      pendings.push(fs.writeFile(`/f${index}.txt`, 'abc').catch(() => undefined));
    }
    await waitFor(
      () => wired.connection.received.filter((message) => message.kind === 'Twrite').length >= 6,
      'every write dispatched',
    );
    wired.connection.close(1011, 'synthetic');
    await Promise.all(pendings);

    const drained = fs.drainOperationFailures();
    assert.equal(drained.entries.length, 3);
    // The fourth is **counted**, not dropped in silence: a bounded channel that
    // quietly forgot its overflow would be worse than no channel at all.
    assert.equal(drained.dropped, 3);
  });

  it('bounds at the documented 64 by default', () => {
    assert.equal(MAX_OPERATION_FAILURES, 64);
  });
});
