/** A valid `agent-tunnel.fs.v1` descriptor, and the pieces to bend it with. */

import type { Descriptor } from '../../src/descriptor.ts';
import { LIMIT_CEILINGS } from '../../src/descriptor.ts';

export function descriptorFixture(overrides: Partial<Descriptor> = {}): Descriptor {
  return {
    schemaVersion: 'agent-tunnel.fs.v1',
    deviceId: 'device-123',
    serviceId: 'workspace',
    grantRevision: 'rev-7',
    availability: 'online',
    capabilityStatus: 'current',
    transport: { type: 'websocket', subprotocol: 'agent-tunnel.9p.v1', dialect: '9P2000.L' },
    root: { path: '/', pathStyle: 'virtual-posix', caseSensitivity: 'sensitive', readOnly: false },
    operations: [
      'readFile',
      'readStream',
      'writeFile',
      'writeStream',
      'stat',
      'readDirectory',
      'mkdir',
      'remove',
      'copy',
      'rename',
      'chmod',
      'utimes',
      'realpath',
    ],
    features: {
      atomicRename: false,
      nativeAppend: false,
      exclusiveCreate: true,
      symlinks: false,
      hardLinks: false,
      birthTime: false,
      fsync: false,
      conditionalWrites: false,
      versioning: false,
      objectMetadata: false,
      publicUrls: false,
      signedUrls: false,
      serverCopy: false,
      serverSearch: false,
    },
    limits: { ...LIMIT_CEILINGS },
    ...overrides,
  };
}
