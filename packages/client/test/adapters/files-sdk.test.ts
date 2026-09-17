/**
 * The Files SDK adapter's object view, and the outcomes it has to flatten.
 *
 * Offline, over the loopback harness. The framework's error class is the
 * stand-in from `wiring.ts`, with upstream's own retry predicate copied beside
 * it; the real `Files` wrapper with retries enabled is `test/peers/`.
 */

import { strict as assert } from 'node:assert';
import { after, describe, it } from 'node:test';

import { createFilesAdapter, type FilesAdapter } from '../../src/adapters/files-sdk.ts';
import { FilesystemError } from '../../src/errors.ts';
import { KeyRefusal, pathForKey } from '../../src/adapters/keys.ts';
import { PathRefusal } from '../../src/paths.ts';
import { descriptorFixture } from '../harness/descriptor.ts';
import {
  closeAll,
  StandInFilesError,
  upstreamWouldRetry,
  waitFor,
  wire,
  type Wired,
} from './wiring.ts';
import type { FakeProvider } from '../harness/provider.ts';

after(closeAll);

const bounds = { maxPathBytes: 4096, maxPathComponents: 256 };
const utf8 = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

async function adapterOver(
  seed: Record<string, string | Uint8Array> = {},
  overrides = {},
  configure?: (provider: FakeProvider) => void,
): Promise<{ adapter: FilesAdapter; wired: Wired }> {
  const wired = await wire(seed, overrides, configure ?? (() => {}));
  return {
    adapter: createFilesAdapter({ remote: wired.remote, FilesError: StandInFilesError }),
    wired,
  };
}

const failure = async (run: () => Promise<unknown>): Promise<StandInFilesError> => {
  try {
    await run();
  } catch (error) {
    assert.ok(error instanceof StandInFilesError, `expected a FilesError, got ${String(error)}`);
    return error;
  }
  throw new Error('expected a rejection');
};

describe('keys are relative, and the namespace refuses the rest', () => {
  it('maps a key to its virtual path and back', () => {
    assert.equal(pathForKey('notes.txt', bounds), '/notes.txt');
    assert.equal(pathForKey('a/b/c.bin', bounds), '/a/b/c.bin');
  });

  it('refuses the two key-shaped inputs under their own rule', () => {
    assert.throws(() => pathForKey('', bounds), (error: KeyRefusal) => error.rule === 'KEY_EMPTY');
    assert.throws(
      () => pathForKey('/notes.txt', bounds),
      (error: KeyRefusal) => error.rule === 'KEY_ABSOLUTE',
    );
    assert.throws(
      () => pathForKey('photos/', bounds),
      (error: KeyRefusal) => error.rule === 'KEY_TRAILING_SEPARATOR',
    );
  });

  it("defers everything else to gate 1's rules, by gate 1's names", () => {
    const cases: Array<[string, string]> = [
      ['../secrets', 'PATH_DOTDOT_COMPONENT'],
      ['./here', 'PATH_DOT_COMPONENT'],
      ['a//b', 'PATH_EMPTY_COMPONENT'],
      ['a\\b', 'PATH_BACKSLASH'],
      ['C:/x', 'PATH_COLON'],
      ['CON', 'PATH_RESERVED_DEVICE_NAME'],
      ['notes.', 'PATH_TRAILING_SPACE_OR_DOT'],
      ['a\u0000b', 'PATH_NUL'],
    ];
    for (const [key, rule] of cases) {
      assert.throws(
        () => pathForKey(key, bounds),
        (error: PathRefusal) => error.rule === rule,
        `key ${JSON.stringify(key)}`,
      );
    }
  });

  it('treats a percent sign as a literal and never decodes it into traversal', () => {
    // `%2e%2e` is a name, not `..`. Decoding it would be the silent repair the
    // namespace exists to prevent.
    assert.equal(pathForKey('%2e%2e/x', bounds), '/%2e%2e/x');
  });
});

describe('the advertised capability surface matches what the methods do', () => {
  it('advertises no metadata, no cache control, no server copy and no signed URL', async () => {
    const { adapter } = await adapterOver();
    assert.equal(adapter.supportsMetadata, false);
    assert.equal(adapter.supportsCacheControl, false);
    assert.equal(adapter.supportsServerSideCopy, false);
    assert.deepEqual(adapter.signedUrl, { supported: false });
    // Absent entirely, so upstream fails every compare-and-set before I/O
    // rather than this adapter emulating one with a stat.
    assert.equal(adapter.conditional, undefined);
    // Implemented explicitly, so upstream does not substitute copy + delete.
    assert.equal(typeof adapter.move, 'function');
  });

  it('url and signedUploadUrl are permanent, nonretryable, and invent no URL', async () => {
    const { adapter } = await adapterOver();
    for (const call of [
      async () => adapter.url('a.txt'),
      async () => adapter.signedUploadUrl('a.txt', { expiresIn: 60 }),
    ]) {
      const error = await failure(call);
      assert.equal(error.code, 'Provider');
      assert.equal(error.permanent, true);
      assert.equal(upstreamWouldRetry(error), false);
      assert.match(error.message, /^ENOTSUP/u);
    }
  });

  it('refuses a delimiter it does not implement, having advertised the one it does', async () => {
    const { adapter } = await adapterOver({ 'a.txt': 'x' });
    assert.equal(adapter.supportsDelimiter, true);
    const error = await failure(async () => adapter.list({ delimiter: '|' }));
    assert.equal(error.code, 'Provider');
    assert.match(error.message, /ENOTSUP \(list:delimiter\)/u);
  });

  it('refuses user metadata and cache control rather than dropping them', async () => {
    const { adapter } = await adapterOver();
    const metadata = await failure(async () =>
      adapter.upload('a.txt', 'x', { metadata: { owner: 'x' } }),
    );
    assert.match(metadata.message, /ENOTSUP \(upload:metadata\)/u);
    const cache = await failure(async () => adapter.upload('a.txt', 'x', { cacheControl: 'max-age=1' }));
    assert.match(cache.message, /ENOTSUP \(upload:cacheControl\)/u);
  });
});

describe('objects over a real socket', () => {
  it('uploads bytes, creating the parent directories the key implies', async () => {
    const { adapter, wired } = await adapterOver();
    const result = await adapter.upload('deep/nested/notes.txt', 'hello');
    assert.equal(result.key, 'deep/nested/notes.txt');
    assert.equal(result.size, 5);
    assert.equal(result.contentType, 'application/octet-stream');
    assert.equal(utf8(wired.provider.read('/deep/nested/notes.txt') as Uint8Array), 'hello');
    assert.ok(typeof result.lastModified === 'number');
    // No ETag is invented from an ordinary stat.
    assert.equal(result.etag, undefined);
  });

  it('heads without reading, and the body accessors read when asked', async () => {
    const { adapter, wired } = await adapterOver({ 'notes.txt': 'hello world' });
    const head = await adapter.head('notes.txt');
    assert.equal(head.size, 11);
    assert.equal(head.type, 'application/octet-stream');
    assert.equal(head.etag, undefined);
    assert.equal(head.metadata, undefined);
    assert.equal(
      wired.connection.received.some((message) => message.kind === 'Tread'),
      false,
      'head must not read the body',
    );
    assert.equal(await head.text(), 'hello world');
    assert.ok(wired.connection.received.some((message) => message.kind === 'Tread'));
  });

  it("downloads an inclusive range, which is not slice's", async () => {
    const { adapter } = await adapterOver({ 'notes.txt': 'abcdefghij' });
    const whole = await adapter.download('notes.txt');
    assert.equal(await whole.text(), 'abcdefghij');
    // `{ start: 0, end: 3 }` is the first **four** bytes.
    const ranged = await adapter.download('notes.txt', { range: { start: 0, end: 3 } });
    assert.equal(ranged.size, 4);
    assert.equal(await ranged.text(), 'abcd');
    const open = await adapter.download('notes.txt', { range: { start: 7 } });
    assert.equal(open.size, 3);
    assert.equal(await open.text(), 'hij');
  });

  it('refuses a range that is not one', async () => {
    const { adapter } = await adapterOver({ 'notes.txt': 'abc' });
    const error = await failure(async () => adapter.download('notes.txt', { range: { start: 5, end: 1 } }));
    assert.match(error.message, /EINVAL \(download:range\)/u);
  });

  it('exists is false only for a confirmed absence', async () => {
    const { adapter } = await adapterOver({ 'notes.txt': 'x' });
    assert.equal(await adapter.exists('notes.txt'), true);
    assert.equal(await adapter.exists('missing.txt'), false);
    // An invalid key is not an absent object: it is a request this adapter
    // cannot make, and reporting `false` would say the export does not hold it.
    const error = await failure(async () => adapter.exists('../escape'));
    assert.equal(error.code, 'Provider');
    assert.match(error.message, /PATH_DOTDOT_COMPONENT/u);
  });

  it('deletes a regular file and refuses a directory', async () => {
    const { adapter, wired } = await adapterOver({ 'dir/a.txt': 'x' });
    await adapter.delete('dir/a.txt');
    assert.equal(wired.provider.has('/dir/a.txt'), false);
    // "directory deletion is not an object delete", and reporting it as an
    // absent object would be the silent no-op the contract forbids.
    const error = await failure(async () => adapter.delete('dir'));
    assert.equal(error.code, 'Conflict');
    assert.equal(upstreamWouldRetry(error), false);
  });

  it('moves with a native rename rather than a copy and a delete', async () => {
    const { adapter, wired } = await adapterOver({ 'a.txt': 'payload' });
    // `move` is optional upstream, and implementing it is the point: without it
    // the SDK substitutes copy + delete.
    const move = adapter.move;
    assert.ok(move !== undefined);
    await move.call(adapter, 'a.txt', 'b/c.txt');
    assert.equal(utf8(wired.provider.read('/b/c.txt') as Uint8Array), 'payload');
    assert.equal(wired.provider.has('/a.txt'), false);
    const kinds = wired.connection.received.map((message) => message.kind);
    assert.ok(kinds.includes('Trename'), 'expected a rename on the wire');
    assert.equal(kinds.includes('Tunlinkat'), false, 'a rename is not a delete');
  });

  it('copies by composing a read and a write, with no server-side copy claim', async () => {
    const { adapter, wired } = await adapterOver({ 'a.txt': 'payload' });
    await adapter.copy('a.txt', 'copy/a.txt');
    assert.equal(utf8(wired.provider.read('/copy/a.txt') as Uint8Array), 'payload');
    assert.equal(utf8(wired.provider.read('/a.txt') as Uint8Array), 'payload');
  });
});

describe('listing is object-key prefix matching, bounded and paginated', () => {
  const tree = {
    'a.txt': '1',
    'photos/cover.jpg': '2',
    'photos/2023/x.jpg': '3',
    'photos/2024/y.jpg': '4',
    'notes/todo.md': '5',
  };

  it('lists regular-file keys and never an empty directory', async () => {
    const { adapter, wired } = await adapterOver(tree);
    // An empty directory is a prefix with nothing under it, so it has no object
    // entry: "empty directories are intentionally not object entries".
    await wired.remote.mkdir('/empty');
    const page = await adapter.list();
    const keys = page.items.map((item) => item.key).sort();
    assert.deepEqual(keys, [
      'a.txt',
      'notes/todo.md',
      'photos/2023/x.jpg',
      'photos/2024/y.jpg',
      'photos/cover.jpg',
    ]);
    assert.equal(page.cursor, undefined);
  });

  it('matches a prefix that is not a whole directory name', async () => {
    const { adapter } = await adapterOver(tree);
    const page = await adapter.list({ prefix: 'pho' });
    assert.equal(page.items.length, 3);
    assert.ok(page.items.every((item) => item.key.startsWith('photos/')));
  });

  it('folds subdirectories into common prefixes with the one delimiter it takes', async () => {
    const { adapter } = await adapterOver(tree);
    const page = await adapter.list({ prefix: 'photos/', delimiter: '/' });
    assert.deepEqual(
      page.items.map((item) => item.key),
      ['photos/cover.jpg'],
    );
    assert.deepEqual((page.prefixes ?? []).sort(), ['photos/2023/', 'photos/2024/']);
  });

  it('pages with an opaque cursor and never silently restarts', async () => {
    const { adapter } = await adapterOver(tree);
    const first = await adapter.list({ limit: 2 });
    assert.equal(first.items.length, 2);
    assert.ok(typeof first.cursor === 'string');
    const cursor = first.cursor;
    assert.ok(cursor !== undefined);
    const second = await adapter.list({ limit: 10, cursor });
    assert.equal(second.items.length, 3);
    assert.equal(second.cursor, undefined);
    const all = [...first.items, ...second.items].map((item) => item.key).sort();
    assert.deepEqual(new Set(all).size, 5);

    // A cursor is single use: continuing it twice would page the same walk
    // twice, and re-running the query from the start would hand back page one
    // as though it were page two.
    const reused = await failure(async () => adapter.list({ limit: 10, cursor }));
    assert.match(reused.message, /EINVAL \(list:cursor\)/u);
  });

  it('binds a cursor to its own query', async () => {
    const { adapter } = await adapterOver(tree);
    const first = await adapter.list({ limit: 1, prefix: 'photos/' });
    const cursor = first.cursor;
    assert.ok(cursor !== undefined);
    const error = await failure(async () => adapter.list({ limit: 1, prefix: 'notes/', cursor }));
    assert.match(error.message, /EINVAL \(list:cursor-query\)/u);
  });

  it('releasing an adapter drops its cursors and touches nothing else', async () => {
    const { adapter, wired } = await adapterOver(tree);
    const first = await adapter.list({ limit: 1 });
    const cursor = first.cursor;
    assert.ok(cursor !== undefined);
    adapter.release();
    const error = await failure(async () => adapter.list({ limit: 1, cursor }));
    assert.match(error.message, /EINVAL \(list:cursor\)/u);
    // The borrowed client is untouched: another borrower is still using it.
    assert.equal(wired.remote.state, 'ready');
    assert.equal((await adapter.head('a.txt')).size, 1);
  });

  it('fails explicitly on the traversal budget instead of returning a short complete page', async () => {
    const { adapter } = await adapterOver(tree, {
      limits: { ...descriptorFixture().limits, maxTraversalEntries: 2 },
    });
    const error = await failure(async () => adapter.list());
    // The budget fires inside the client's own directory enumeration, which is
    // where the entries are counted; the adapter's own budget backs it up for a
    // walk that never enumerates.
    assert.match(error.message, /EFBIG \((list|readDirectory)\)/u);
  });
});

describe('outcomes, and what Files SDK can and cannot say about them', () => {
  it('maps the errno vocabulary onto the four semantic codes', async () => {
    const { adapter } = await adapterOver({ 'dir/a.txt': 'x' });
    assert.equal((await failure(async () => adapter.head('missing.txt'))).code, 'NotFound');
    assert.equal((await failure(async () => adapter.head('dir'))).code, 'Conflict');
  });

  it('never produces a retryable error, for any failure it can raise', async () => {
    const { adapter } = await adapterOver({ 'dir/a.txt': 'x' });
    const raised = [
      await failure(async () => adapter.head('missing.txt')),
      await failure(async () => adapter.head('dir')),
      await failure(async () => adapter.url('a.txt')),
      await failure(async () => adapter.exists('../escape')),
      await failure(async () => adapter.list({ delimiter: '|' })),
    ];
    for (const error of raised) {
      assert.equal(upstreamWouldRetry(error), false, error.message);
    }
  });

  it('an unknown mutation is a permanent Provider error carrying the outcome as cause', async () => {
    // A dispatched `Twrite` with no reply: the device may have performed it and
    // no code on the wire says which.
    const { adapter, wired } = await adapterOver({}, {}, (provider) => {
      provider.swallow.add('Twrite');
    });
    const pending = adapter.upload('fresh.txt', 'abc');
    await waitFor(() => wired.connection.received.some((message) => message.kind === 'Twrite'));
    wired.connection.close(1011, 'synthetic');
    const error = await failure(async () => pending);

    assert.equal(error.code, 'Provider');
    assert.equal(error.permanent, true);
    assert.equal(upstreamWouldRetry(error), false);
    // `applied` upstream means a conditional mutation **committed**. "Do not
    // misuse upstream `applied` as 'may have happened.'"
    assert.equal(error.applied, false);
    assert.equal(error.appliedEtag, undefined);

    // The outcome itself survives in the cause and nowhere else: Files SDK has
    // no field that distinguishes `partial` from `unknown`, and this adapter
    // does not invent one.
    const cause = error.cause;
    assert.ok(cause instanceof FilesystemError);
    assert.equal(cause.outcome, 'unknown');
    assert.equal(cause.retryable, false);
  });

  it('a partial composite is the same permanent Provider error, distinguished only by its cause', async () => {
    // `copy` creates its destination before reading its source, so a source
    // that is absent leaves a created file behind: `partial`, never
    // `not_started`.
    const { adapter } = await adapterOver({});
    const error = await failure(async () => adapter.copy('missing.txt', 'out.txt'));
    assert.equal(error.code, 'Provider');
    assert.equal(error.permanent, true);
    assert.equal(error.applied, false);
    const cause = error.cause;
    assert.ok(cause instanceof FilesystemError);
    assert.equal(cause.outcome, 'partial');

    // Both outcomes arrive as the same `code`, `permanent` and `applied`. That
    // is the flattening this interface forces, asserted rather than assumed.
    assert.equal(error.code, 'Provider');
  });

  it('carries no path, name or content in the message it hands the framework', async () => {
    const { adapter } = await adapterOver({});
    const error = await failure(async () => adapter.head('very-secret-name.txt'));
    assert.equal(error.message.includes('very-secret-name'), false, error.message);
    // A code and the request that failed, and nothing else.
    assert.match(error.message, /^ENOENT \(T?walk\)$/u);
  });
});

describe('the composites this adapter owns, and the floors they carry', () => {
  // Every one of these creates the key's parent directories first. A directory
  // made and a failure afterwards is a change to the export the failing step
  // knows nothing about — the class of defect the shared client spent three
  // rounds removing from `writeInto`, `mkdir` and `remove`, sitting one layer
  // up in the adapter.

  it('a move whose source is absent, after its destination parents were made, is partial', async () => {
    const { adapter, wired } = await adapterOver({});
    const move = adapter.move;
    assert.ok(move !== undefined);
    const error = await failure(async () => move.call(adapter, 'missing.txt', 'new/dir/b.txt'));

    // `/new/dir` stands in the export. `NotFound` with an outcome of
    // `not_started` would tell the caller nothing happened.
    assert.equal(wired.provider.has('/new/dir'), true);
    assert.equal(error.code, 'Provider');
    assert.equal(error.permanent, true);
    assert.equal(upstreamWouldRetry(error), false);
    const cause = error.cause;
    assert.ok(cause instanceof FilesystemError);
    assert.equal(cause.outcome, 'partial');
  });

  it('an upload whose create is refused, after its parents were made, is partial', async () => {
    const { adapter, wired } = await adapterOver({}, {}, (provider) => {
      provider.failAfter.set('Tlcreate', { after: 0, ecode: 13 });
    });
    const error = await failure(async () => adapter.upload('new/dir/a.txt', 'hello'));
    assert.equal(wired.provider.has('/new/dir'), true);
    assert.equal(error.code, 'Provider');
    const cause = error.cause;
    assert.ok(cause instanceof FilesystemError);
    assert.equal(cause.outcome, 'partial');
  });

  it('a copy whose create is refused, after its parents were made, is partial', async () => {
    // The refusal is `Tlcreate`, so the shared client's own `copy` has applied
    // nothing and reports `failed`. The floor here is the adapter's alone:
    // `/new/dir` exists because this call made it.
    const { adapter, wired } = await adapterOver({ 'a.txt': 'payload' }, {}, (provider) => {
      provider.failAfter.set('Tlcreate', { after: 0, ecode: 13 });
    });
    const error = await failure(async () => adapter.copy('a.txt', 'new/dir/b.txt'));
    assert.equal(wired.provider.has('/new/dir'), true);
    assert.equal(error.code, 'Provider');
    const cause = error.cause;
    assert.ok(cause instanceof FilesystemError);
    assert.equal(cause.outcome, 'partial');
  });

  it('a parent chain that already existed sets no floor', async () => {
    // The floor is what was **applied**, not what was attempted. `mkdir`
    // reports how many directories it made, and a chain that was already there
    // made none — so this failure is the plain absence it is.
    const { adapter } = await adapterOver({ 'new/dir/keep.txt': 'x' });
    const move = adapter.move;
    assert.ok(move !== undefined);
    const error = await failure(async () => move.call(adapter, 'missing.txt', 'new/dir/b.txt'));
    assert.equal(error.code, 'NotFound');
    const cause = error.cause;
    assert.ok(cause instanceof FilesystemError);
    assert.equal(cause.outcome, 'not_started');
  });

  it('a confirmed upload is not failed by its courtesy stat', async () => {
    // The write is acknowledged; the trailing `stat` only fills in the optional
    // `lastModified`. Reporting a completed upload as a failure — and as one
    // whose outcome is the stat's own `not_started` — would tell a caller the
    // key was never written while it holds exactly what was sent.
    const { adapter, wired } = await adapterOver({}, {}, (provider) => {
      provider.failAfter.set('Tgetattr', { after: 0, ecode: 13 });
    });
    const result = await adapter.upload('a.txt', 'hello');
    assert.equal(result.key, 'a.txt');
    assert.equal(result.size, 5);
    assert.equal(result.lastModified, undefined, 'absent rather than invented');
    assert.equal(utf8(wired.provider.read('/a.txt') as Uint8Array), 'hello');
  });
});

describe('a page is a page the adapter can actually produce', () => {
  it('lists more keys than the session may have requests in flight', async () => {
    // Each item is a `stat`: a walk, a getattr and a clunk. The session refuses
    // a request beyond `maxInflightRequests` **locally** with
    // `RESOURCE_EXHAUSTED`, and the profile pins that at 64 — so a page fanned
    // out at once could never be produced for a directory with more keys than
    // the quota, and `DEFAULT_PAGE` of 100 would be a number this adapter can
    // never fulfil.
    const quota = descriptorFixture().limits.maxInflightRequests;
    const count = quota + 6;
    const seed: Record<string, string> = {};
    for (let index = 0; index < count; index += 1) {
      seed[`f${index}.txt`] = 'x';
    }
    const { adapter } = await adapterOver(seed);
    const page = await adapter.list();
    assert.equal(page.items.length, count);
    assert.equal(page.cursor, undefined);
    assert.equal(new Set(page.items.map((item) => item.key)).size, count);
  });

  it('stops dispatching stats once one of them has failed', async () => {
    // `Promise.all` rejects on the first failure, so without a shared flag the
    // other workers keep pulling from the queue and keep sending requests —
    // spending the quota this bound exists to protect, after the caller already
    // holds an error, with their own failures swallowed because nothing awaits
    // them any more.
    //
    // The peer fails **once**, deliberately. A peer that failed every stat
    // would kill every worker at the same moment, and a pool that had kept
    // going would still have looked bounded; one failure among successes is the
    // shape where the survivors drain the rest of the page. On this shape the
    // unflagged version dispatches all 40.
    const keys = 40;
    const seed: Record<string, string> = {};
    for (let index = 0; index < keys; index += 1) {
      seed[`f${index}.txt`] = 'x';
    }
    const { adapter, wired } = await adapterOver(seed, {}, (provider) => {
      provider.failAfter.set('Tgetattr', { after: 3, ecode: 13, times: 1 });
    });
    await failure(async () => adapter.list());
    const stats = (): number =>
      wired.connection.received.filter((message) => message.kind === 'Tgetattr').length;

    // Let everything settle, then require it to stay settled. The rejection
    // reaches the caller before the surviving workers next reach their check,
    // so the count still moves for one turn; what must not happen is that it
    // keeps moving.
    await new Promise((resolve) => setTimeout(resolve, 30));
    const settled = stats();
    await new Promise((resolve) => setTimeout(resolve, 60));
    assert.equal(stats(), settled, 'no stat may be dispatched once the failure has been observed');

    // The substantive claim: the rest of the page is never stat-ed. Without the
    // flag this is exactly `keys`, because the workers whose own stats
    // succeeded drain the queue after the caller already holds the error.
    assert.ok(settled < keys, `the rest of the page must not be stat-ed, saw ${settled} of ${keys}`);
    // The irreducible window: a worker whose own stat succeeded can pass its
    // check before the failing worker's rejection handler runs, so up to one
    // further pool may start. It is bounded by the pool, not by the page.
    const pool = statConcurrencyFor(descriptorFixture().limits.maxInflightRequests);
    assert.ok(settled <= 2 * pool, `expected at most two pools, saw ${settled}`);
  });
});

/** The pool size the adapter derives, mirrored here so the bound is named once. */
function statConcurrencyFor(maxInflightRequests: number): number {
  return Math.max(1, Math.floor(maxInflightRequests / 4));
}

describe('a read-only export denies every mutation entry point', () => {
  it('refuses upload, delete, copy and move before anything reaches the socket', async () => {
    const { adapter, wired } = await adapterOver({ 'a.txt': 'x' }, {
      root: { ...descriptorFixture().root, readOnly: true },
      operations: ['readFile', 'readStream', 'stat', 'readDirectory'],
    });
    const move = adapter.move;
    assert.ok(move !== undefined);
    for (const call of [
      async () => adapter.upload('b.txt', 'x'),
      async () => adapter.delete('a.txt'),
      async () => adapter.copy('a.txt', 'b.txt'),
      async () => move.call(adapter, 'a.txt', 'b.txt'),
    ]) {
      const error = await failure(call);
      assert.match(error.message, /^ENOTSUP/u);
      assert.equal(upstreamWouldRetry(error), false);
    }
    // Not "nothing was sent" — `delete` stats first, which a read grant allows.
    // What must be true is that **no mutating opcode** reached the socket.
    const mutating = new Set(['Tlcreate', 'Twrite', 'Tmkdir', 'Tunlinkat', 'Trename', 'Trenameat', 'Tsetattr']);
    assert.deepEqual(
      wired.connection.received.filter((message) => mutating.has(message.kind)),
      [],
    );
    // Reads still work, which is what a read-only profile is for.
    assert.equal((await adapter.head('a.txt')).size, 1);
  });
});
