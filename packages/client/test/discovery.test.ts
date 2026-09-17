/**
 * Discovery and the upgrade, over a real loopback socket.
 *
 * The descriptor `GET`, its validation, the HTTP failure vocabulary, the
 * `grantRevision` header, the subprotocol, and the handshake checks. The
 * server is `test/harness/endpoint.ts` — a real `node:http` server speaking
 * real RFC 6455, and **not** a relay: see that file for what this cannot prove.
 */

import { strict as assert } from 'node:assert';
import { after, describe, it } from 'node:test';

import { connectFilesystem, fetchDescriptor } from '../src/filesystem.ts';
import { validateDescriptor, GRANT_REVISION_HEADER } from '../src/descriptor.ts';
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
    ];
    for (const [what, value] of bend) {
      it(what, () => {
        assert.throws(() => validateDescriptor(value), (error: FilesystemError) => {
          assert.equal(error.code, 'MALFORMED_DESCRIPTOR');
          return true;
        });
      });
    }

    it('accepts the checked-in example’s shape', () => {
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
