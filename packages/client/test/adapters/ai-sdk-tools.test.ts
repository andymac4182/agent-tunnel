/**
 * The AI SDK live directory tools (`createFilesystemTools`), driven the way
 * `ai`'s tool loop drives them: validate the input through the Standard
 * Schema, then call `execute` with an abort signal.
 *
 * Offline, like the rest of `npm test`: the module imports `ai` by type only,
 * so these suites run with `node_modules` deleted. The same tools are handed to
 * the real `generateText` in `test/peers/contract.peers.ts`.
 */

import { strict as assert } from 'node:assert';
import { after, describe, it } from 'node:test';

import {
  createFilesystemTools,
  DEFAULT_MAX_READ_BYTES,
  type FilesystemTools,
} from '../../src/adapters/ai-sdk-tools.ts';
import { closeAll, waitFor, wire, type Wired } from './wiring.ts';
import type { FakeProvider } from '../harness/provider.ts';

after(closeAll);

interface StandardShape {
  '~standard': {
    validate: (value: unknown) => { value: unknown } | { issues: unknown[] } | Promise<unknown>;
    jsonSchema?: { input: (options: { target: string }) => unknown };
  };
}

function standard(schema: unknown): StandardShape['~standard'] {
  assert.ok(typeof schema === 'object' && schema !== null && '~standard' in schema);
  return (schema as StandardShape)['~standard'];
}

/** Validate like `ai` does, then execute. Returns the result or the issues. */
async function call(
  tools: FilesystemTools,
  name: keyof FilesystemTools,
  input: unknown,
  signal?: AbortSignal,
): Promise<unknown> {
  const tool = tools[name];
  assert.ok(tool !== undefined, `tool ${String(name)} is offered`);
  const verdict = (await standard(tool.inputSchema).validate(input)) as { value?: unknown; issues?: unknown };
  if (verdict.issues !== undefined) {
    return { invalid: verdict.issues };
  }
  assert.ok(tool.execute !== undefined);
  return await tool.execute(verdict.value as never, {
    toolCallId: 'call-1',
    messages: [],
    ...(signal === undefined ? {} : { abortSignal: signal }),
  } as never);
}

async function toolsOver(
  seed: Record<string, string | Uint8Array>,
  overrides = {},
  configure?: (provider: FakeProvider) => void,
  options: Omit<Parameters<typeof createFilesystemTools>[0], 'remote'> = {},
): Promise<{ tools: FilesystemTools; wired: Wired }> {
  const wired = await wire(seed, overrides, configure ?? (() => {}));
  return { tools: createFilesystemTools({ remote: wired.remote, ...options }), wired };
}

describe('the tool set a grant advertises', () => {
  it('offers list, read and stat, and write only on a writable grant', async () => {
    const writable = await toolsOver({ 'a.txt': 'a' });
    assert.deepEqual(Object.keys(writable.tools).sort(), ['list_directory', 'read_file', 'stat', 'write_file']);

    const readOnly = await toolsOver({ 'a.txt': 'a' }, {
      root: { path: '/', pathStyle: 'virtual-posix', caseSensitivity: 'sensitive', readOnly: true },
      operations: ['readFile', 'readStream', 'stat', 'readDirectory'],
    });
    assert.deepEqual(Object.keys(readOnly.tools).sort(), ['list_directory', 'read_file', 'stat']);

    const narrowed = await toolsOver({ 'a.txt': 'a' }, {}, undefined, { readOnly: true });
    assert.equal(narrowed.tools.write_file, undefined, 'the application may narrow, never widen');
  });

  it('publishes a closed JSON Schema the model sees, with no endpoint, token or export field', async () => {
    const { tools } = await toolsOver({});
    for (const [name, tool] of Object.entries(tools)) {
      const json = standard(tool?.inputSchema).jsonSchema?.input({ target: 'draft-07' }) as {
        type: string;
        additionalProperties: boolean;
        properties: Record<string, unknown>;
        required: string[];
      };
      assert.equal(json.type, 'object', name);
      assert.equal(json.additionalProperties, false, name);
      assert.ok(json.required.includes('path'), name);
      for (const forbidden of ['endpoint', 'token', 'export', 'device', 'service', 'grant']) {
        assert.equal(forbidden in json.properties, false, `${name} exposes ${forbidden}`);
      }
    }
  });

  it('refuses malformed input before execute: unknown keys, wrong types, missing path', async () => {
    const { tools, wired } = await toolsOver({ 'a.txt': 'a' });
    const before = wired.connection.received.length;
    assert.ok('invalid' in ((await call(tools, 'read_file', { path: '/a.txt', token: 'x' })) as object));
    assert.ok('invalid' in ((await call(tools, 'read_file', { path: 7 })) as object));
    assert.ok('invalid' in ((await call(tools, 'read_file', { maxBytes: 3 })) as object));
    assert.ok('invalid' in ((await call(tools, 'read_file', { path: '/a.txt', maxBytes: 0 })) as object));
    assert.ok('invalid' in ((await call(tools, 'write_file', { path: '/b.txt' })) as object));
    assert.ok('invalid' in ((await call(tools, 'list_directory', 'not an object')) as object));
    assert.equal(wired.connection.received.length, before, 'nothing reached the wire');
  });
});

describe('list_directory', () => {
  it('lists immediate children, sorted, with their kinds', async () => {
    const { tools } = await toolsOver({ 'b.txt': 'b', 'a.txt': 'a', 'docs/c.md': 'c' });
    const result = await call(tools, 'list_directory', { path: '/' });
    assert.deepEqual(result, {
      ok: true,
      path: '/',
      entries: [
        { name: 'a.txt', kind: 'file' },
        { name: 'b.txt', kind: 'file' },
        { name: 'docs', kind: 'directory' },
      ],
      truncated: false,
    });
  });

  it('stops at maxEntries and says so', async () => {
    const seed: Record<string, string> = {};
    for (let i = 0; i < 10; i += 1) {
      seed[`f${i}.txt`] = String(i);
    }
    const { tools } = await toolsOver(seed, {}, undefined, { maxEntries: 4 });
    const result = (await call(tools, 'list_directory', { path: '/' })) as { entries: unknown[]; truncated: boolean };
    assert.equal(result.entries.length, 4);
    assert.equal(result.truncated, true);

    const exact = await toolsOver(seed, {}, undefined, { maxEntries: 10 });
    const whole = (await call(exact.tools, 'list_directory', { path: '/' })) as { entries: unknown[]; truncated: boolean };
    assert.equal(whole.entries.length, 10);
    assert.equal(whole.truncated, false, 'exactly at the bound is not truncated');
  });

  it('reports absence as a model-visible failure, not a throw', async () => {
    const { tools } = await toolsOver({});
    assert.deepEqual(await call(tools, 'list_directory', { path: '/missing' }), {
      ok: false,
      code: 'ENOENT',
      // The shared client's own classification of an absent walk target.
      outcome: 'not_started',
      retrySafe: true,
    });
  });

  it('reports a refused path by its rule, before anything is sent', async () => {
    const { tools, wired } = await toolsOver({});
    const before = wired.connection.received.length;
    const result = (await call(tools, 'list_directory', { path: '/../etc' })) as { ok: boolean; outcome: string };
    assert.equal(result.ok, false);
    assert.equal(result.outcome, 'not_started');
    assert.equal(wired.connection.received.length, before);
  });
});

describe('read_file', () => {
  it('returns UTF-8 text whole when it fits', async () => {
    const { tools } = await toolsOver({ 'docs/a.md': '# Title\nbody\n' });
    assert.deepEqual(await call(tools, 'read_file', { path: '/docs/a.md' }), {
      ok: true,
      path: '/docs/a.md',
      encoding: 'utf8',
      content: '# Title\nbody\n',
      bytesReturned: 13,
      truncated: false,
    });
  });

  it('bounds what it returns by bytes received, at the bound and one beyond', async () => {
    const { tools } = await toolsOver({ 'exact.txt': 'abcd', 'over.txt': 'abcde' });
    const exact = (await call(tools, 'read_file', { path: '/exact.txt', maxBytes: 4 })) as Record<string, unknown>;
    assert.equal(exact['content'], 'abcd');
    assert.equal(exact['truncated'], false);
    const over = (await call(tools, 'read_file', { path: '/over.txt', maxBytes: 4 })) as Record<string, unknown>;
    assert.equal(over['content'], 'abcd');
    assert.equal(over['bytesReturned'], 4);
    assert.equal(over['truncated'], true);
  });

  it('caps a model-requested bound at the configured one', async () => {
    const { tools } = await toolsOver({ 'big.txt': 'x'.repeat(40) }, {}, undefined, { maxReadBytes: 16 });
    const result = (await call(tools, 'read_file', { path: '/big.txt' })) as Record<string, unknown>;
    assert.equal(result['bytesReturned'], 16);
    assert.equal(result['truncated'], true);
    // The schema itself advertises the cap to the model, and a larger request
    // is clamped rather than honoured.
    const json = standard(tools.read_file.inputSchema).jsonSchema?.input({ target: 'draft-07' }) as {
      properties: { maxBytes: { maximum: number } };
    };
    assert.equal(json.properties.maxBytes.maximum, 16);
    const asked = (await call(tools, 'read_file', { path: '/big.txt', maxBytes: 17 })) as Record<string, unknown>;
    assert.equal(asked['bytesReturned'], 16);
    assert.equal(DEFAULT_MAX_READ_BYTES, 65536);
  });

  it('returns binary content as base64 rather than as mangled text', async () => {
    const binary = new Uint8Array([0xff, 0x00, 0xfe, 0x01]);
    const { tools } = await toolsOver({ 'blob.bin': binary });
    const result = (await call(tools, 'read_file', { path: '/blob.bin' })) as Record<string, unknown>;
    assert.equal(result['encoding'], 'base64');
    assert.deepEqual(new Uint8Array(Buffer.from(result['content'] as string, 'base64')), binary);
  });

  it('keeps a multi-byte character cut by the bound as text', async () => {
    const { tools } = await toolsOver({ 'e.txt': 'aé' }); // 'é' is two bytes
    const result = (await call(tools, 'read_file', { path: '/e.txt', maxBytes: 2 })) as Record<string, unknown>;
    assert.equal(result['encoding'], 'utf8');
    assert.equal(result['truncated'], true);
    assert.equal(result['bytesReturned'], 2);
  });

  it('propagates the abort signal and re-throws a cancellation', async () => {
    const { tools, wired } = await toolsOver({ 'slow.txt': 'abc' }, {}, (provider) => {
      provider.swallow.add('Tread');
    });
    const controller = new AbortController();
    const pending = call(tools, 'read_file', { path: '/slow.txt' }, controller.signal);
    await waitFor(() => wired.connection.received.some((message) => message.kind === 'Tread'), 'Tread');
    controller.abort();
    await assert.rejects(pending);
  });
});

describe('stat', () => {
  it('reports kind, size as a decimal string, and an ISO modification time', async () => {
    const { tools } = await toolsOver({ 'a.txt': 'hello' });
    const result = (await call(tools, 'stat', { path: '/a.txt' })) as Record<string, unknown>;
    assert.equal(result['ok'], true);
    assert.equal(result['kind'], 'file');
    assert.equal(result['size'], '5');
    assert.match(result['modifiedAt'] as string, /^\d{4}-\d{2}-\d{2}T/u);
  });
});

describe('write_file', () => {
  it('creates a file exclusively by default and refuses to replace one', async () => {
    const { tools, wired } = await toolsOver({ 'keep.txt': 'original' });
    assert.deepEqual(await call(tools, 'write_file', { path: '/new.txt', content: 'fresh' }), {
      ok: true,
      path: '/new.txt',
      bytesWritten: 5,
      outcome: 'applied',
    });
    assert.equal(new TextDecoder().decode(wired.provider.read('/new.txt')), 'fresh');

    const refused = (await call(tools, 'write_file', { path: '/keep.txt', content: 'x' })) as Record<string, unknown>;
    assert.equal(refused['ok'], false);
    assert.equal(refused['code'], 'EEXIST');
    assert.equal(refused['outcome'], 'failed');
    assert.equal(refused['retrySafe'], false, 'a failed mutation is a floor, not proof nothing applied');
    assert.equal(new TextDecoder().decode(wired.provider.read('/keep.txt')), 'original');

    const replaced = await call(tools, 'write_file', { path: '/keep.txt', content: 'x', overwrite: true });
    assert.equal((replaced as Record<string, unknown>)['ok'], true);
    assert.equal(new TextDecoder().decode(wired.provider.read('/keep.txt')), 'x');
  });

  it('refuses over-large text before dispatch, as not_started', async () => {
    const { tools, wired } = await toolsOver({}, {}, undefined, { maxWriteBytes: 4 });
    const before = wired.connection.received.length;
    assert.deepEqual(await call(tools, 'write_file', { path: '/x.txt', content: 'abcde' }), {
      ok: false,
      code: 'EFBIG',
      outcome: 'not_started',
      retrySafe: true,
    });
    assert.equal(wired.connection.received.length, before);
    assert.equal(wired.provider.has('/x.txt'), false);
  });

  it('reports a device-refused write as failed and not retry-safe', async () => {
    // filesystem-api.md: "`failed` on a mutation therefore means 'at least
    // this much', never 'nothing applied'" — an Rlerror can follow a node the
    // device already made. Only `not_started` licenses a retry of a write.
    const { tools, wired } = await toolsOver({}, {}, (provider) => {
      provider.failAfter.set('Tlcreate', { after: 0, ecode: 13 });
    });
    const result = (await call(tools, 'write_file', { path: '/denied.txt', content: 'x' })) as Record<string, unknown>;
    assert.equal(result['ok'], false);
    assert.equal(result['code'], 'EACCES');
    assert.equal(result['outcome'], 'failed', 'one refused request: the wire floor');
    assert.equal(result['retrySafe'], false);
    assert.ok(wired.connection.received.some((message) => message.kind === 'Tlcreate'));
  });

  it('keeps a failed read retry-safe, because a read changes nothing', async () => {
    const { tools } = await toolsOver({});
    const result = (await call(tools, 'read_file', { path: '/absent.txt' })) as Record<string, unknown>;
    assert.equal(result['ok'], false);
    assert.equal(result['retrySafe'], true);
  });

  it('reports an unanswered write as unknown and never retry-safe', async () => {
    const { tools, wired } = await toolsOver({}, {}, (provider) => {
      provider.swallow.add('Twrite');
    });
    const pending = call(tools, 'write_file', { path: '/u.txt', content: 'maybe' });
    await waitFor(() => wired.connection.received.some((message) => message.kind === 'Twrite'), 'Twrite');
    wired.connection.close(1011, 'synthetic');
    const result = (await pending) as Record<string, unknown>;
    assert.equal(result['ok'], false);
    assert.equal(result['outcome'], 'unknown');
    assert.equal(result['retrySafe'], false);
  });
});

describe('options', () => {
  it('refuses a non-positive bound at construction', async () => {
    const { wired } = await toolsOver({});
    assert.throws(() => createFilesystemTools({ remote: wired.remote, maxReadBytes: 0 }), RangeError);
    assert.throws(() => createFilesystemTools({ remote: wired.remote, maxEntries: 1.5 }), RangeError);
  });
});
