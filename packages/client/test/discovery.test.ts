/**
 * Discovery and the upgrade, over a real loopback socket.
 *
 * The descriptor `GET`, its validation, the HTTP failure vocabulary, the
 * `grantRevision` header, the subprotocol, and the handshake checks. The
 * server is `test/harness/endpoint.ts` — a real `node:http` server speaking
 * real RFC 6455, and **not** a relay: see that file for what this cannot prove.
 */

import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import { connectFilesystem, fetchDescriptor } from '../src/filesystem.ts';
import { validateDescriptor, GRANT_REVISION_HEADER } from '../src/descriptor.ts';
import { isLoopback, isTlsVerificationFailure } from '../src/websocket.ts';
import { FilesystemError } from '../src/errors.ts';
import { descriptorFixture } from './harness/descriptor.ts';
import { grantRevisionOf, startEndpoint, type Endpoint } from './harness/endpoint.ts';
import { FakeProvider } from './harness/provider.ts';

const open: Endpoint[] = [];
after(async () => {
  for (const endpoint of open) {
    await endpoint.close();
  }
});

async function endpointWith(options: Parameters<typeof startEndpoint>[0]): Promise<Endpoint> {
  const endpoint = await startEndpoint(options);
  open.push(endpoint);
  return endpoint;
}

const token = (): string => 'synthetic-consumer-token';

describe('the descriptor', () => {
  it('is fetched with a bearer token and validated', async () => {
    const endpoint = await endpointWith({ descriptor: descriptorFixture() });
    const descriptor = await fetchDescriptor({
      endpoint: endpoint.url,
      token,
      allowInsecureLoopback: true,
    });
    assert.equal(descriptor.schemaVersion, 'agent-tunnel.fs.v1');
    assert.equal(descriptor.grantRevision, 'rev-7');
    assert.equal(endpoint.lastDescriptorHeaders['authorization'], 'Bearer synthetic-consumer-token');
  });

  it('refuses a non-loopback endpoint that is not https', async () => {
    await assert.rejects(
      fetchDescriptor({ endpoint: 'http://relay.example/v1/devices/d/services/s/fs', token }),
      (error: FilesystemError) => error.code === 'INSECURE_ENDPOINT',
    );
  });

  it('refuses plain http even to loopback unless the harness is asked for', async () => {
    const endpoint = await endpointWith({ descriptor: descriptorFixture() });
    await assert.rejects(
      fetchDescriptor({ endpoint: endpoint.url, token }),
      (error: FilesystemError) => error.code === 'INSECURE_ENDPOINT',
    );
  });

  describe('maps every HTTP failure the contract tabulates', () => {
    const cases: [number, string, string][] = [
      [401, 'UNAUTHENTICATED', 'UNAUTHENTICATED'],
      [403, 'ACCESS_DENIED', 'ACCESS_DENIED'],
      [404, 'EXPORT_NOT_FOUND', 'EXPORT_NOT_FOUND'],
      [405, 'METHOD_NOT_ALLOWED', 'METHOD_NOT_ALLOWED'],
      [409, 'CAPABILITIES_CHANGED', 'CAPABILITIES_CHANGED'],
      [429, 'RESOURCE_EXHAUSTED', 'RESOURCE_EXHAUSTED'],
      [503, 'DEVICE_OFFLINE', 'DEVICE_OFFLINE'],
      [503, 'BACKEND_UNAVAILABLE', 'BACKEND_UNAVAILABLE'],
      [503, 'ROTATION_FREEZE', 'ROTATION_FREEZE'],
    ];
    for (const [status, code, expected] of cases) {
      it(`${status} ${code}`, async () => {
        const endpoint = await endpointWith({
          descriptorFailure: {
            status,
            body: { error: { code, message: 'diagnostic', requestId: 'r' } },
          },
        });
        await assert.rejects(
          fetchDescriptor({ endpoint: endpoint.url, token, allowInsecureLoopback: true }),
          (error: FilesystemError) => {
            assert.equal(error.code, expected);
            assert.equal(error.outcome, 'not_started');
            return true;
          },
        );
      });
    }

    it('falls back to the status when the body is not the contract’s shape', async () => {
      const endpoint = await endpointWith({
        descriptorFailure: { status: 403, body: { message: 'a proxy wrote this' } },
      });
      await assert.rejects(
        fetchDescriptor({ endpoint: endpoint.url, token, allowInsecureLoopback: true }),
        (error: FilesystemError) => error.code === 'ACCESS_DENIED',
      );
    });
  });

  describe('validation refuses a descriptor that cannot be honoured', () => {
    const bend: [string, unknown][] = [
      ['a different schema', { ...descriptorFixture(), schemaVersion: 'agent-tunnel.fs.v2' }],
      [
        'another dialect',
        {
          ...descriptorFixture(),
          transport: { type: 'websocket', subprotocol: 'agent-tunnel.9p.v1', dialect: '9P2000' },
        },
      ],
      ['an empty operation list', { ...descriptorFixture(), operations: [] }],
      ['an unknown operation', { ...descriptorFixture(), operations: ['teleport'] }],
      [
        'a limit above the profile ceiling',
        {
          ...descriptorFixture(),
          limits: { ...descriptorFixture().limits, maxMessageBytes: 65537 },
        },
      ],
      [
        'a zero limit, which must not read as unlimited',
        { ...descriptorFixture(), limits: { ...descriptorFixture().limits, maxFids: 0 } },
      ],
      [
        'inconsistent limits',
        {
          ...descriptorFixture(),
          limits: { ...descriptorFixture().limits, maxQueuedBytes: 1024, maxMessageBytes: 65536 },
        },
      ],
      [
        'a missing feature flag',
        (() => {
          const value = descriptorFixture() as unknown as Record<string, Record<string, unknown>>;
          const features = { ...value['features'] };
          delete features['fsync'];
          return { ...value, features };
        })(),
      ],
      ['an identifier outside the narrow set', { ...descriptorFixture(), deviceId: 'a device' }],
      // `additionalProperties: false` is the schema's rule at every level, not
      // only for `features`: an unknown key is where a future field with a
      // meaning would arrive, and ignoring it would honour a descriptor this
      // client does not understand.
      ['an unknown key at the top level', { ...descriptorFixture(), surprise: true }],
      [
        'an unknown key in transport',
        {
          ...descriptorFixture(),
          transport: { ...descriptorFixture().transport, compression: 'deflate' },
        },
      ],
      ['an unknown key in root', { ...descriptorFixture(), root: { ...descriptorFixture().root, hostPath: '/tmp' } }],
      [
        'an unknown key in limits',
        { ...descriptorFixture(), limits: { ...descriptorFixture().limits, maxRetries: 3 } },
      ],
    ];
    for (const [what, value] of bend) {
      it(what, () => {
        assert.throws(() => validateDescriptor(value), (error: FilesystemError) => {
          assert.equal(error.code, 'MALFORMED_DESCRIPTOR');
          return true;
        });
      });
    }

    it('accepts the checked-in example itself, not merely a fixture shaped like it', () => {
      // Read from `docs/contracts/filesystem-capabilities.example.json`, so the
      // rules this validator enforces — `additionalProperties: false` above
      // all — cannot drift away from the document they claim to implement. A
      // fixture written beside the validator would agree with it by
      // construction.
      const example: unknown = JSON.parse(
        readFileSync(
          join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'docs', 'contracts', 'filesystem-capabilities.example.json'),
          'utf8',
        ),
      );
      const parsed = validateDescriptor(example);
      assert.equal(parsed.schemaVersion, 'agent-tunnel.fs.v1');
      assert.equal(parsed.root.readOnly, true);
      assert.doesNotThrow(() => validateDescriptor(descriptorFixture()));
    });
  });
});

describe('the upgrade', () => {
  it('carries the descriptor’s grant revision and the subprotocol', async () => {
    const provider = new FakeProvider();
    const endpoint = await endpointWith({
      descriptor: descriptorFixture(),
      onRequest: provider.handle,
    });
    const remote = await connectFilesystem({
      endpoint: endpoint.url,
      token,
      allowInsecureLoopback: true,
    });
    assert.equal(grantRevisionOf(endpoint.lastUpgradeHeaders), 'rev-7');
    assert.equal(
      endpoint.lastUpgradeHeaders['sec-websocket-protocol'],
      'agent-tunnel.9p.v1',
    );
    assert.equal(endpoint.lastUpgradeHeaders['authorization'], 'Bearer synthetic-consumer-token');
    assert.equal(remote.state, 'ready');
    await remote.close();
  });

  it('refuses a 101 that did not select the subprotocol', async () => {
    const endpoint = await endpointWith({
      descriptor: descriptorFixture(),
      omitSubprotocol: true,
    });
    await assert.rejects(
      connectFilesystem({ endpoint: endpoint.url, token, allowInsecureLoopback: true }),
      (error: FilesystemError) => error.code === 'SUBPROTOCOL_REQUIRED',
    );
  });

  it('refuses a 101 whose accept hash is wrong', async () => {
    const endpoint = await endpointWith({ descriptor: descriptorFixture(), wrongAccept: true });
    await assert.rejects(
      connectFilesystem({ endpoint: endpoint.url, token, allowInsecureLoopback: true }),
      (error: FilesystemError) => error.code === 'INVALID_UPGRADE',
    );
  });

  it('refuses an extension nothing offered, compression included', async () => {
    const endpoint = await endpointWith({
      descriptor: descriptorFixture(),
      selectExtension: 'permessage-deflate',
    });
    await assert.rejects(
      connectFilesystem({ endpoint: endpoint.url, token, allowInsecureLoopback: true }),
      (error: FilesystemError) => error.code === 'INVALID_UPGRADE',
    );
  });

  it('maps a refused upgrade to the contract’s code, not to a socket failure', async () => {
    const endpoint = await endpointWith({
      descriptor: descriptorFixture(),
      upgradeFailure: {
        status: 409,
        body: { error: { code: 'CAPABILITIES_CHANGED', message: 'stale', requestId: 'r' } },
      },
    });
    await assert.rejects(
      connectFilesystem({ endpoint: endpoint.url, token, allowInsecureLoopback: true }),
      (error: FilesystemError) => {
        assert.equal(error.code, 'CAPABILITIES_CHANGED');
        assert.equal(error.operation, 'upgrade');
        return true;
      },
    );
  });

  it('does not open a session to an offline device', async () => {
    const endpoint = await endpointWith({
      descriptor: descriptorFixture({ availability: 'offline' }),
    });
    await assert.rejects(
      connectFilesystem({ endpoint: endpoint.url, token, allowInsecureLoopback: true }),
      (error: FilesystemError) => error.code === 'DEVICE_OFFLINE',
    );
    assert.equal(endpoint.connections.length, 0, 'no upgrade should have been attempted');
  });

  it('is bounded: a peer that answers 101 and then says nothing does not hang', async () => {
    // Every step of `connectFilesystem` is bounded. The fetch has the caller's
    // signal, the upgrade has both a signal and a deadline, and the `Tversion`
    // — which occupies no tag slot and was therefore skipped by the request
    // timer in an earlier round — is on the deadline like any other request.
    const endpoint = await endpointWith({
      descriptor: descriptorFixture({
        limits: { ...descriptorFixture().limits, requestTimeoutSeconds: 1 },
      }),
      onRequest: () => {
        // Answer nothing at all, including the version handshake.
      },
    });
    const started = Date.now();
    await assert.rejects(
      connectFilesystem({ endpoint: endpoint.url, token, allowInsecureLoopback: true }),
      (error: FilesystemError) => {
        assert.equal(error.code, 'DEADLINE_EXCEEDED');
        // The `Tversion` was dispatched and mutates nothing, so `failed` — and
        // never `unknown`, which would say a side effect might have happened
        // during a handshake that cannot have one.
        assert.equal(error.outcome, 'failed');
        return true;
      },
    );
    assert.ok(Date.now() - started < 5000, 'it did not wait for ever');
  });

  it('is cancellable: a signal aborted during the handshake ends the connect', async () => {
    const controller = new AbortController();
    const endpoint = await endpointWith({
      descriptor: descriptorFixture(),
      onRequest: () => {
        controller.abort();
      },
    });
    await assert.rejects(
      connectFilesystem({
        endpoint: endpoint.url,
        token,
        allowInsecureLoopback: true,
        signal: controller.signal,
      }),
      (error: FilesystemError) => {
        assert.equal(error.code, 'ABORTED');
        return true;
      },
    );
  });

  it('refuses a plain-http endpoint whose host is loopback only by NAME', async () => {
    // `localhost` is a name a hosts file or a DNS answer can point anywhere,
    // and with the insecure opt-in set that would have sent the bearer token in
    // clear to whatever it resolved to. Loopback is decided by address.
    await assert.rejects(
      fetchDescriptor({
        endpoint: 'http://localhost:1/v1/devices/d/services/s/fs',
        token,
        allowInsecureLoopback: true,
      }),
      (error: FilesystemError) => error.code === 'INSECURE_ENDPOINT',
    );
    for (const host of ['127.0.0.1', '127.1.2.3', '[::1]']) {
      assert.equal(isLoopback(new URL(`http://${host}:1/fs`)), true, host);
    }
    for (const host of ['localhost', 'example.com', '128.0.0.1', '10.0.0.1']) {
      assert.equal(isLoopback(new URL(`http://${host}:1/fs`)), false, host);
    }
  });

  it('reports a transport failure as a FilesystemError, and a TLS failure as not retryable', async () => {
    // A bare `TypeError` out of `fetch` gave a caller branching on `code`
    // nothing to branch on; and a certificate this side could not verify is not
    // an outage, so it must not look retryable.
    const endpoint = await endpointWith({ descriptor: descriptorFixture() });
    const url = new URL(endpoint.url);
    url.port = '1';
    await assert.rejects(
      fetchDescriptor({ endpoint: url.toString(), token, allowInsecureLoopback: true }),
      (error: FilesystemError) => {
        assert.ok(error instanceof FilesystemError);
        assert.equal(error.code, 'BACKEND_UNAVAILABLE');
        assert.equal(error.outcome, 'not_started');
        return true;
      },
    );
    for (const code of [
      'ERR_TLS_CERT_ALTNAME_INVALID',
      'DEPTH_ZERO_SELF_SIGNED_CERT',
      'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
      'CERT_HAS_EXPIRED',
    ]) {
      assert.equal(isTlsVerificationFailure({ code }), true, code);
    }
    for (const code of ['ECONNREFUSED', 'ENOTFOUND', 'ETIMEDOUT']) {
      assert.equal(isTlsVerificationFailure({ code }), false, code);
    }
  });

  it('sends the version handshake first and attaches the root once', async () => {
    const provider = new FakeProvider();
    const endpoint = await endpointWith({
      descriptor: descriptorFixture(),
      onRequest: provider.handle,
    });
    const remote = await connectFilesystem({
      endpoint: endpoint.url,
      token,
      allowInsecureLoopback: true,
    });
    const received = endpoint.connections[0]?.received ?? [];
    assert.equal(received[0]?.kind, 'Tversion');
    assert.equal(received[0]?.tag, 0xffff, 'Tversion uses NOTAG');
    assert.equal(received[1]?.kind, 'Tattach');
    assert.notEqual(received[1]?.tag, 0xffff, 'nothing else may use NOTAG');
    const attach = received[1];
    assert.ok(attach?.kind === 'Tattach');
    assert.equal(attach.afid, 0xffffffff);
    assert.equal(attach.uname, '');
    assert.equal(attach.aname, '');
    assert.equal(attach.nUname, 0xffffffff);
    assert.equal(received.filter((message) => message.kind === 'Tattach').length, 1);
    await remote.close();
  });

  it('never sends a second descriptor’s revision on a reconnect it does not do', async () => {
    // There is no reconnect: a closed client is not reusable, so the header
    // cannot go stale behind the caller's back.
    const provider = new FakeProvider();
    const endpoint = await endpointWith({
      descriptor: descriptorFixture(),
      onRequest: provider.handle,
    });
    const remote = await connectFilesystem({
      endpoint: endpoint.url,
      token,
      allowInsecureLoopback: true,
    });
    await remote.close();
    await assert.rejects(
      remote.stat('/notes.txt'),
      (error: FilesystemError) => error.code === 'SESSION_LOST',
    );
    assert.equal(remote.state, 'closed');
    assert.equal(GRANT_REVISION_HEADER, 'X-Agent-Tunnel-Grant-Revision');
  });
});
