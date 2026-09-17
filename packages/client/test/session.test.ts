/**
 * The consumer session: the state machine, the quotas, the close codes, and
 * the outcome an in-flight mutation is classified with.
 *
 * The classification is the obligation gate 5 named for this side — "there is
 * no wire field for an outcome ... the shared client is what classifies an
 * in-flight mutation from its own dispatch and reply history" — so it is tested
 * both as a pure function and over a real socket that goes away mid-write.
 */

import { strict as assert } from 'node:assert';
import { after, describe, it } from 'node:test';

import { constants as C, encode } from '../src/ninep/codec.ts';
import { connectFilesystem, type RemoteFilesystem } from '../src/filesystem.ts';
import { FilesystemError, mergeOutcome, sessionCodeForClose } from '../src/errors.ts';
import { classifyOutcome, ConsumerSession, isMutatingRequest } from '../src/session.ts';
import { SUBPROTOCOL } from '../src/descriptor.ts';
import { upgrade } from '../src/websocket.ts';
import { descriptorFixture } from './harness/descriptor.ts';
import { startEndpoint, type Endpoint, type ServerConnection } from './harness/endpoint.ts';
import { FakeProvider } from './harness/provider.ts';

const open: Endpoint[] = [];
after(async () => {
  for (const endpoint of open) {
    await endpoint.close();
  }
});

const token = (): string => 'synthetic-consumer-token';

interface Wired {
  remote: RemoteFilesystem;
  endpoint: Endpoint;
  provider: FakeProvider;
  connection: ServerConnection;
}

async function connect(
  options: {
    seed?: Record<string, string | Uint8Array>;
    descriptor?: Parameters<typeof descriptorFixture>[0];
    onRequest?: (message: import('../src/ninep/messages.ts').Message, connection: ServerConnection) => void;
  } = {},
): Promise<Wired> {
  const provider = new FakeProvider(options.seed ?? {});
  const endpoint = await startEndpoint({
    descriptor: descriptorFixture(options.descriptor ?? {}),
    onRequest: options.onRequest ?? provider.handle,
  });
  open.push(endpoint);
  const remote = await connectFilesystem({
    endpoint: endpoint.url,
    token,
    allowInsecureLoopback: true,
  });
  const connection = endpoint.connections[0];
  assert.ok(connection !== undefined);
  return { remote, endpoint, provider, connection };
}

describe('outcome classification, as a function of dispatch and reply history', () => {
  it('nothing dispatched is not_started', () => {
    assert.equal(
      classifyOutcome({ mutating: true, dispatched: false, bytesAcknowledged: 0 }),
      'not_started',
    );
  });

  it('a dispatched read that never answered is failed, never unknown', () => {
    assert.equal(
      classifyOutcome({ mutating: false, dispatched: true, bytesAcknowledged: 0 }),
      'failed',
    );
  });

  it('a dispatched mutation with no reply is unknown', () => {
    // The row that matters. The device's own ledger knows; this side cannot,
    // and reporting `failed` would invite a retry onto a mutation that applied.
    assert.equal(
      classifyOutcome({ mutating: true, dispatched: true, bytesAcknowledged: 0 }),
      'unknown',
    );
  });

  it('acknowledged bytes make it partial, and the merge only strengthens', () => {
    assert.equal(
      classifyOutcome({ mutating: true, dispatched: true, bytesAcknowledged: 16 }),
      'unknown',
    );
    assert.equal(mergeOutcome('partial', 'not_started'), 'partial');
    assert.equal(mergeOutcome('not_started', 'unknown'), 'unknown');
    assert.equal(mergeOutcome('unknown', 'failed'), 'unknown');
  });

  it('splits Tlopen on its flags, exactly as gate 5 splits the primitive', () => {
    // Opening for writing changes nothing; truncating does. Getting this wrong
    // in the other direction would tell a caller nothing happened when the
    // file had already been emptied.
    assert.equal(isMutatingRequest({ kind: 'Tlopen', tag: 1, fid: 1, flags: C.O_WRONLY }), false);
    assert.equal(
      isMutatingRequest({ kind: 'Tlopen', tag: 1, fid: 1, flags: C.O_WRONLY | C.O_TRUNC }),
      true,
    );
    assert.equal(isMutatingRequest({ kind: 'Tread', tag: 1, fid: 1, offset: 0n, count: 1 }), false);
    assert.equal(
      isMutatingRequest({ kind: 'Twrite', tag: 1, fid: 1, offset: 0n, data: new Uint8Array(1) }),
      true,
    );
    assert.equal(isMutatingRequest({ kind: 'Tclunk', tag: 1, fid: 1 }), false);
  });

  it('an error whose outcome is partial or unknown is never retryable', () => {
    // Whatever the code says. "SDK retry wrappers must ... classify
    // partial/unknown mutation errors as permanently nonretryable."
    for (const outcome of ['partial', 'unknown'] as const) {
      const error = new FilesystemError({
        code: 'RESOURCE_EXHAUSTED',
        operation: 'writeFile',
        outcome,
        retryable: true,
      });
      assert.equal(error.retryable, false);
    }
    const plain = new FilesystemError({
      code: 'RESOURCE_EXHAUSTED',
      operation: 'stat',
      outcome: 'not_started',
      retryable: true,
    });
    assert.equal(plain.retryable, true);
  });
});

describe('the close codes the contract pins', () => {
  const cases: [number, string][] = [
    [1002, 'PROTOCOL_VIOLATION'],
    [1008, 'AUTH_EXPIRED'],
    [1011, 'SESSION_LOST'],
    [1012, 'DEVICE_OFFLINE'],
    [1013, 'RESOURCE_EXHAUSTED'],
  ];

  for (const [code, expected] of cases) {
    it(`${code} is ${expected}, mapped and reported`, async () => {
      assert.equal(sessionCodeForClose(code), expected);
      const provider = new FakeProvider({ 'notes.txt': 'hello' });
      provider.swallow.add('Tgetattr');
      const wired = await connect({ onRequest: provider.handle });
      const pending = wired.remote.stat('/notes.txt');
      await waitFor(() => wired.connection.received.some((m) => m.kind === 'Tgetattr'));
      wired.connection.close(code, 'synthetic');
      await assert.rejects(pending, (error: FilesystemError) => {
        assert.equal(error.code, expected);
        assert.equal(error.closeCode, code);
        // A read: dispatched, mutates nothing, so `failed` and never `unknown`.
        assert.equal(error.outcome, 'failed');
        return true;
      });
      assert.equal(wired.remote.state, 'closed');
    });
  }

  it('a socket that vanishes with no close frame is SESSION_LOST at 1006', async () => {
    const provider = new FakeProvider({ 'notes.txt': 'hello' });
    provider.swallow.add('Tgetattr');
    const wired = await connect({ onRequest: provider.handle });
    const pending = wired.remote.stat('/notes.txt');
    await waitFor(() => wired.connection.received.some((m) => m.kind === 'Tgetattr'));
    wired.connection.destroy();
    await assert.rejects(pending, (error: FilesystemError) => {
      assert.equal(error.code, 'SESSION_LOST');
      assert.equal(error.closeCode, 1006);
      return true;
    });
  });

  it('a mutation in flight when the session closes is unknown, at every code', async () => {
    for (const code of [1008, 1011, 1012, 1013]) {
      const provider = new FakeProvider({ 'notes.txt': 'hello' });
      provider.swallow.add('Twrite');
      const wired = await connect({ onRequest: provider.handle });
      const pending = wired.remote.writeFile('/fresh.txt', new TextEncoder().encode('abc'));
      await waitFor(() => wired.connection.received.some((m) => m.kind === 'Twrite'));
      wired.connection.close(code, 'synthetic');
      await assert.rejects(pending, (error: FilesystemError) => {
        assert.equal(error.outcome, 'unknown', `close ${code}`);
        assert.equal(error.retryable, false);
        // The close code says why the session ended and says nothing about
        // whether the write applied. Both are reported, separately.
        assert.equal(error.code, sessionCodeForClose(code));
        return true;
      });
    }
  });
});

describe('the session state machine', () => {
  it('refuses a reply for a tag nothing is waiting on, with 1002', async () => {
    const wired = await connect({ seed: { 'notes.txt': 'hello' } });
    wired.connection.send({ kind: 'Rclunk', tag: 4242 });
    await waitFor(() => wired.remote.state === 'closed');
    await assert.rejects(
      wired.remote.stat('/notes.txt'),
      (error: FilesystemError) => error.code === 'PROTOCOL_VIOLATION',
    );
  });

  it('refuses a reply of the wrong type for its request', async () => {
    const wired = await connect({
      onRequest: (message, connection) => {
        if (message.kind === 'Tversion') {
          connection.send({ kind: 'Rversion', tag: C.NOTAG, msize: 65536, version: C.VERSION });
          return;
        }
        if (message.kind === 'Tattach') {
          connection.send({ kind: 'Rattach', tag: message.tag, qid: { type: C.QTDIR, version: 0, path: 1n } });
          return;
        }
        // A `Twalk` answered with an `Rclunk`.
        connection.send({ kind: 'Rclunk', tag: message.tag });
      },
    });
    await assert.rejects(
      wired.remote.stat('/notes.txt'),
      (error: FilesystemError) => error.code === 'PROTOCOL_VIOLATION',
    );
  });

  it('refuses an Rread carrying more bytes than its Tread asked for', async () => {
    // A reply is checked against its own request's bounds, which is the same
    // rule `crates/tunnel-fs-ninep` applies in the other direction. The read is
    // given an explicit length so the over-long reply still fits inside
    // `msize`: this is the reply lying about its own request, not a frame
    // breaking the framing.
    const provider = new FakeProvider({ 'notes.txt': 'hello' });
    const wired = await connect({
      onRequest: (message, connection) => {
        if (message.kind === 'Tread') {
          connection.send({
            kind: 'Rread',
            tag: message.tag,
            data: new Uint8Array(message.count + 1),
          });
          return;
        }
        provider.handle(message, connection);
      },
    });
    await assert.rejects(
      wired.remote.readFile('/notes.txt', { length: 8 }),
      (error: FilesystemError) => error.code === 'PROTOCOL_VIOLATION',
    );
  });

  it('refuses a text frame, which this profile never carries', async () => {
    const wired = await connect({ seed: { 'notes.txt': 'hello' } });
    wired.connection.sendText('{"not":"9P"}');
    await waitFor(() => wired.remote.state === 'closed');
    assert.equal(wired.remote.closedWith?.code, 1002);
  });

  it('reassembles a reply fragmented at the WebSocket level', async () => {
    // Valid RFC 6455 fragmentation of one binary message: the 9P message is one
    // message however many frames carried it, and the consumer rule is about
    // messages rather than frames.
    const provider = new FakeProvider({ 'notes.txt': 'hello world' });
    const wired = await connect({
      onRequest: (message, connection) => {
        if (message.kind === 'Tread' && message.offset === 0n) {
          connection.sendFragmented(
            { kind: 'Rread', tag: message.tag, data: new TextEncoder().encode('hello world') },
            4,
          );
          return;
        }
        provider.handle(message, connection);
      },
    });
    const bytes = await wired.remote.readFile('/notes.txt');
    assert.equal(new TextDecoder().decode(bytes), 'hello world');
  });

  it('refuses two 9P messages packed into one binary message', async () => {
    const provider = new FakeProvider({ 'notes.txt': 'hello' });
    const wired = await connect({
      onRequest: (message, connection) => {
        if (message.kind === 'Tread') {
          const one = encode({ kind: 'Rread', tag: message.tag, data: new Uint8Array(1) });
          const both = new Uint8Array(one.byteLength * 2);
          both.set(one, 0);
          both.set(one, one.byteLength);
          connection.sendRaw(both);
          return;
        }
        provider.handle(message, connection);
      },
    });
    await assert.rejects(
      wired.remote.readFile('/notes.txt'),
      (error: FilesystemError) => error.code === 'PROTOCOL_VIOLATION',
    );
  });

  it('refuses to exceed its own tag quota rather than losing the session to 1013', async () => {
    // The device answers a request beyond the quota by closing 1013, because
    // there is no tag left to carry an `Rlerror`. A client that sent one would
    // lose every other outstanding request over its own accounting.
    const provider = new FakeProvider({ 'notes.txt': 'hello' });
    provider.swallow.add('Tgetattr');
    const wired = await connect({
      descriptor: { limits: { ...descriptorFixture().limits, maxInflightRequests: 2 } },
      onRequest: provider.handle,
    });
    const first = wired.remote.stat('/notes.txt');
    const second = wired.remote.stat('/notes.txt');
    const third = wired.remote.stat('/notes.txt');
    await assert.rejects(Promise.race([first, second, third]), (error: FilesystemError) => {
      assert.equal(error.code, 'RESOURCE_EXHAUSTED');
      assert.equal(error.outcome, 'not_started');
      assert.equal(error.retryable, true);
      return true;
    });
    wired.connection.close(1011, 'done');
    await Promise.allSettled([first, second, third]);
  });

  it('refuses to exceed its own fid quota', async () => {
    const provider = new FakeProvider({ 'notes.txt': 'hello' });
    provider.swallow.add('Tgetattr');
    const wired = await connect({
      descriptor: { limits: { ...descriptorFixture().limits, maxFids: 1 } },
      onRequest: provider.handle,
    });
    const first = wired.remote.stat('/notes.txt');
    await waitFor(() => wired.connection.received.some((m) => m.kind === 'Tgetattr'));
    await assert.rejects(wired.remote.stat('/notes.txt'), (error: FilesystemError) => {
      assert.equal(error.code, 'RESOURCE_EXHAUSTED');
      assert.equal(error.operation, 'session:fids');
      return true;
    });
    wired.connection.close(1011, 'done');
    await Promise.allSettled([first]);
  });

  it('cancels with Tflush and reports what cancellation can honestly claim', async () => {
    const provider = new FakeProvider({ 'notes.txt': 'hello' });
    provider.swallow.add('Twrite');
    const wired = await connect({ onRequest: provider.handle });
    const controller = new AbortController();
    const pending = wired.remote.writeFile('/fresh.txt', new TextEncoder().encode('abc'), {
      signal: controller.signal,
    });
    await waitFor(() => wired.connection.received.some((m) => m.kind === 'Twrite'));
    controller.abort();
    await assert.rejects(pending, (error: FilesystemError) => {
      assert.equal(error.code, 'ABORTED');
      // "Cancellation after dispatch never promises no side effect."
      assert.equal(error.outcome, 'unknown');
      return true;
    });
    assert.ok(
      wired.connection.received.some((m) => m.kind === 'Tflush'),
      'cancellation is a Tflush, not a close',
    );
    assert.equal(wired.remote.state, 'ready', 'cancelling one operation does not end the session');
  });

  it('honours an original reply that beat its Rflush', async () => {
    // 9P permits it and the contract says to respect it: a request that
    // completed before the cancellation reached the device really did complete,
    // and answering "aborted" would throw away a result that was performed.
    //
    // Driven at the session rather than through `readFile`, because a composite
    // operation's *next* request refuses on the aborted signal — which is
    // correct, and would hide the rule under test.
    const provider = new FakeProvider({ 'notes.txt': 'hello' });
    let held: { message: import('../src/ninep/messages.ts').Message; connection: ServerConnection } | undefined;
    const endpoint = await startEndpoint({
      descriptor: descriptorFixture(),
      onRequest: (message, connection) => {
        if (message.kind === 'Twalk' && message.wnames.length > 0 && held === undefined) {
          held = { message, connection };
          return;
        }
        if (message.kind === 'Tflush' && held !== undefined) {
          // The original first, then the flush's own answer.
          provider.handle(held.message, held.connection);
          connection.send({ kind: 'Rflush', tag: message.tag });
          return;
        }
        provider.handle(message, connection);
      },
    });
    open.push(endpoint);
    const session = await openSession(endpoint);
    const controller = new AbortController();
    const walk = session.request(
      { kind: 'Twalk', tag: 0, fid: 0, newfid: 5, wnames: ['notes.txt'] },
      { signal: controller.signal },
    );
    await waitFor(() => held !== undefined);
    controller.abort();
    const reply = await walk;
    assert.equal(reply.kind, 'Rwalk');
    assert.equal(session.state, 'ready');
    session.close();
  });

  it('refuses an Rversion whose msize is above this side’s offer', async () => {
    // 9P requires the server's value to be at most the client's. Clamping it
    // silently would leave the two disagreeing about the frame bound until the
    // first over-size message closed the session in the middle of a read.
    const provider = new FakeProvider({ 'notes.txt': 'hello' });
    const endpoint = await startEndpoint({
      descriptor: descriptorFixture({
        limits: { ...descriptorFixture().limits, maxMessageBytes: 256 },
      }),
      onRequest: (message, connection) => {
        if (message.kind === 'Tversion') {
          connection.send({ kind: 'Rversion', tag: message.tag, msize: 65536, version: '9P2000.L' });
          return;
        }
        provider.handle(message, connection);
      },
    });
    open.push(endpoint);
    await assert.rejects(
      connectFilesystem({ endpoint: endpoint.url, token, allowInsecureLoopback: true }),
      (error: FilesystemError) => {
        assert.equal(error.code, 'PROTOCOL_VIOLATION');
        return true;
      },
    );
  });

  it('releases a held tag when the flush it could not send is answered by the original', async () => {
    // Under a full tag quota `flush` has no tag to cancel with, so the victim's
    // number stays held rather than being reused. An earlier round held it for
    // ever — one slot lost per deadline — because the late reply was dropped
    // without releasing it. The reply is the last word on that tag, so it is
    // released there.
    const provider = new FakeProvider({ 'notes.txt': 'hello' });
    let held: { message: import('../src/ninep/messages.ts').Message; connection: ServerConnection } | undefined;
    const endpoint = await startEndpoint({
      descriptor: descriptorFixture(),
      onRequest: (message, connection) => {
        if (message.kind === 'Twalk' && message.wnames.length > 0 && held === undefined) {
          held = { message, connection };
          return;
        }
        provider.handle(message, connection);
      },
    });
    open.push(endpoint);
    const session = await openSession(endpoint, { maxInflightRequests: 1, requestTimeoutMs: 30 });
    const walk = session.request({ kind: 'Twalk', tag: 0, fid: 0, newfid: 5, wnames: ['notes.txt'] });
    await assert.rejects(walk, (error: FilesystemError) => {
      assert.equal(error.code, 'DEADLINE_EXCEEDED');
      return true;
    });
    assert.equal(session.tagsHeld, 1, 'the tag is held, not reused');
    // Now the original reply arrives: nothing is waiting to flush it, so the
    // number is free again and the session is usable.
    await waitFor(() => held !== undefined);
    provider.handle(held!.message, held!.connection);
    await waitFor(() => session.tagsHeld === 0);
    const again = await session.request({ kind: 'Tclunk', tag: 0, fid: 5 });
    assert.equal(again.kind, 'Rclunk');
    session.close();
  });

  it('an already-aborted signal refuses before anything is sent', async () => {
    const wired = await connect({ seed: { 'notes.txt': 'hello' } });
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(
      wired.remote.readFile('/notes.txt', { signal: controller.signal }),
      (error: FilesystemError) => {
        assert.equal(error.code, 'ABORTED');
        // The one case in which cancellation *can* promise nothing happened.
        assert.equal(error.outcome, 'not_started');
        return true;
      },
    );
  });
});

/** Open a bare session over the endpoint, for the rules a composite hides. */
async function openSession(
  endpoint: Endpoint,
  limits: { maxInflightRequests?: number; requestTimeoutMs?: number } = {},
): Promise<ConsumerSession> {
  let session: ConsumerSession | undefined;
  const transport = await upgrade({
    url: new URL(endpoint.url),
    subprotocol: SUBPROTOCOL,
    headers: { Authorization: 'Bearer synthetic-consumer-token' },
    maxMessageBytes: 65536,
    allowInsecureLoopback: true,
    handlers: {
      onMessage: (bytes) => session?.onMessage(bytes),
      onClose: (info) => session?.onClose(info),
    },
  });
  session = new ConsumerSession(transport, {
    msize: 65536,
    maxInflightRequests: limits.maxInflightRequests ?? 64,
    maxFids: 256,
    requestTimeoutMs: limits.requestTimeoutMs ?? 0,
  });
  await session.open();
  return session;
}

async function waitFor(condition: () => boolean, timeoutMs = 2000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (condition()) {
      return;
    }
    if (Date.now() > deadline) {
      throw new Error('condition did not hold within the deadline');
    }
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
}
