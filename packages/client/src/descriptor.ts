/**
 * The capability descriptor: its type, its validation, and its fetch.
 *
 * `docs/filesystem-api.md`: an authenticated HTTPS `GET` with no `Upgrade`
 * answers "a JSON descriptor with `Content-Type: application/json` and
 * `Cache-Control: no-store`". It "is informative, never an authorization
 * credential", so nothing here treats a field of it as permission: every
 * refusal a session takes is the device's, and the descriptor only says what to
 * expect.
 *
 * Validation is by the checked-in schema's own rules
 * (`docs/contracts/filesystem-capabilities.schema.json`), written out rather
 * than fetched: the client must refuse "malformed descriptors, unsupported
 * versions/dialects, inconsistent limits, and untrusted endpoint origins before
 * opening a usable session", and a validator that needed a schema library would
 * be a runtime dependency this package does not have.
 */

import { FilesystemError, type DiscoveryErrorCode } from './errors.ts';

export const SCHEMA_VERSION = 'agent-tunnel.fs.v1';
export const SUBPROTOCOL = 'agent-tunnel.9p.v1';
export const DIALECT = '9P2000.L';
export const GRANT_REVISION_HEADER = 'X-Agent-Tunnel-Grant-Revision';

export type Operation =
  | 'readFile'
  | 'readStream'
  | 'writeFile'
  | 'writeStream'
  | 'appendFile'
  | 'stat'
  | 'readDirectory'
  | 'mkdir'
  | 'remove'
  | 'copy'
  | 'rename'
  | 'chmod'
  | 'utimes'
  | 'symlink'
  | 'link'
  | 'readlink'
  | 'realpath';

export const OPERATIONS: readonly Operation[] = [
  'readFile',
  'readStream',
  'writeFile',
  'writeStream',
  'appendFile',
  'stat',
  'readDirectory',
  'mkdir',
  'remove',
  'copy',
  'rename',
  'chmod',
  'utimes',
  'symlink',
  'link',
  'readlink',
  'realpath',
];

export const FEATURES = [
  'atomicRename',
  'nativeAppend',
  'exclusiveCreate',
  'symlinks',
  'hardLinks',
  'birthTime',
  'fsync',
  'conditionalWrites',
  'versioning',
  'objectMetadata',
  'publicUrls',
  'signedUrls',
  'serverCopy',
  'serverSearch',
] as const;

export type FeatureName = (typeof FEATURES)[number];

export interface Limits {
  maxMessageBytes: number;
  maxInflightRequests: number;
  maxFids: number;
  maxQueuedBytes: number;
  maxBufferedFileBytes: number;
  maxTotalBufferedBytes: number;
  maxPathBytes: number;
  maxPathComponents: number;
  maxTraversalEntries: number;
  maxTraversalDepth: number;
  requestTimeoutSeconds: number;
  defaultOperationTimeoutSeconds: number;
  maxOperationTimeoutSeconds: number;
  sessionIdleSeconds: number;
}

/** The ceilings of the initial profile. Negotiation may only reduce them. */
export const LIMIT_CEILINGS: Limits = {
  maxMessageBytes: 65536,
  maxInflightRequests: 64,
  maxFids: 256,
  maxQueuedBytes: 1048576,
  maxBufferedFileBytes: 16777216,
  maxTotalBufferedBytes: 33554432,
  maxPathBytes: 4096,
  maxPathComponents: 256,
  maxTraversalEntries: 10000,
  maxTraversalDepth: 64,
  requestTimeoutSeconds: 30,
  defaultOperationTimeoutSeconds: 300,
  maxOperationTimeoutSeconds: 3600,
  sessionIdleSeconds: 300,
};

export interface Descriptor {
  schemaVersion: typeof SCHEMA_VERSION;
  deviceId: string;
  serviceId: string;
  grantRevision: string;
  availability: 'online' | 'offline';
  capabilityStatus: 'current' | 'last-known';
  transport: { type: 'websocket'; subprotocol: string; dialect: string };
  root: {
    path: '/';
    pathStyle: 'virtual-posix';
    caseSensitivity: 'sensitive' | 'insensitive-preserving';
    readOnly: boolean;
  };
  operations: Operation[];
  features: Record<FeatureName, boolean>;
  limits: Limits;
}

function malformed(detail: string): never {
  throw new FilesystemError({
    code: 'MALFORMED_DESCRIPTOR',
    operation: `descriptor:${detail}`,
    outcome: 'not_started',
    retryable: false,
  });
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * The schema says `additionalProperties: false` at **every** level, so a key
 * this client does not know about is a descriptor it cannot honour rather than
 * one it can ignore. An earlier round enforced that for `features` only, which
 * made the strictness look like a property of one object instead of the rule it
 * is — and an unknown key is exactly where a future field with a meaning would
 * arrive.
 */
function refuseExtraKeys(value: Record<string, unknown>, allowed: readonly string[], where: string): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      malformed(`${where}-extra`);
    }
  }
}

const IDENTIFIER = /^[A-Za-z0-9._-]{1,128}$/u;

/**
 * Check a parsed descriptor against the contract, and return it typed.
 *
 * Every rule here is the schema's, plus the three gate 1 makes structurally
 * impossible on the device and which a *client* must still check because it is
 * reading bytes from the network: an empty `operations` array must never reach
 * a consumer as though it described a usable export, `availability`/
 * `capabilityStatus` must be consistent, and no limit may exceed the profile's
 * own ceiling — a descriptor may only ever reduce.
 */
export function validateDescriptor(value: unknown): Descriptor {
  if (!isObject(value)) {
    malformed('not-an-object');
  }
  if (value['schemaVersion'] !== SCHEMA_VERSION) {
    malformed('schemaVersion');
  }
  for (const field of ['deviceId', 'serviceId', 'grantRevision'] as const) {
    const text = value[field];
    if (typeof text !== 'string' || !IDENTIFIER.test(text)) {
      malformed(field);
    }
  }
  if (value['availability'] !== 'online' && value['availability'] !== 'offline') {
    malformed('availability');
  }
  if (value['capabilityStatus'] !== 'current' && value['capabilityStatus'] !== 'last-known') {
    malformed('capabilityStatus');
  }
  refuseExtraKeys(
    value,
    [
      'schemaVersion',
      'deviceId',
      'serviceId',
      'grantRevision',
      'availability',
      'capabilityStatus',
      'transport',
      'root',
      'operations',
      'features',
      'limits',
    ],
    'descriptor',
  );
  const transport = value['transport'];
  if (
    !isObject(transport) ||
    transport['type'] !== 'websocket' ||
    transport['subprotocol'] !== SUBPROTOCOL ||
    transport['dialect'] !== DIALECT
  ) {
    // "Reject ... unsupported versions/dialects ... before opening a usable
    // session": a descriptor naming another dialect is refused here rather
    // than discovered after the upgrade.
    malformed('transport');
  }
  refuseExtraKeys(transport, ['type', 'subprotocol', 'dialect'], 'transport');
  const root = value['root'];
  if (
    !isObject(root) ||
    root['path'] !== '/' ||
    root['pathStyle'] !== 'virtual-posix' ||
    (root['caseSensitivity'] !== 'sensitive' &&
      root['caseSensitivity'] !== 'insensitive-preserving') ||
    typeof root['readOnly'] !== 'boolean'
  ) {
    malformed('root');
  }
  refuseExtraKeys(root, ['path', 'pathStyle', 'caseSensitivity', 'readOnly'], 'root');
  const operations = value['operations'];
  if (!Array.isArray(operations) || operations.length === 0) {
    // An empty grant derives an empty operation list, and discovery must
    // answer 403 for such an export rather than serving a descriptor that
    // advertises nothing. A client that met one anyway refuses it rather than
    // connecting to an export it can do nothing with.
    malformed('operations');
  }
  for (const operation of operations) {
    if (typeof operation !== 'string' || !OPERATIONS.includes(operation as Operation)) {
      malformed('operations');
    }
  }
  if (new Set(operations).size !== operations.length) {
    malformed('operations-duplicate');
  }
  const features = value['features'];
  if (!isObject(features)) {
    malformed('features');
  }
  for (const feature of FEATURES) {
    if (typeof features[feature] !== 'boolean') {
      malformed('features');
    }
  }
  if (Object.keys(features).length !== FEATURES.length) {
    malformed('features-extra');
  }
  const limits = value['limits'];
  if (!isObject(limits)) {
    malformed('limits');
  }
  refuseExtraKeys(limits, Object.keys(LIMIT_CEILINGS), 'limits');
  for (const [name, ceiling] of Object.entries(LIMIT_CEILINGS)) {
    const limit = limits[name];
    if (typeof limit !== 'number' || !Number.isInteger(limit) || limit < 1) {
      // Neither zero nor a fraction, so there is no "0 means unlimited"
      // reading to be had on this side either.
      malformed(`limits.${name}`);
    }
    if (limit > ceiling) {
      malformed(`limits.${name}-above-ceiling`);
    }
  }
  const typed = value as unknown as Descriptor;
  if (typed.limits.maxMessageBytes < 256) {
    malformed('limits.maxMessageBytes-below-floor');
  }
  // The cross-field rules gate 1 enforces, checked here for the same reason:
  // a descriptor whose limits contradict one another cannot be honoured.
  if (typed.limits.maxQueuedBytes < typed.limits.maxMessageBytes) {
    malformed('limits.maxQueuedBytes');
  }
  if (typed.limits.maxBufferedFileBytes > typed.limits.maxTotalBufferedBytes) {
    malformed('limits.maxBufferedFileBytes');
  }
  if (typed.limits.defaultOperationTimeoutSeconds > typed.limits.maxOperationTimeoutSeconds) {
    malformed('limits.defaultOperationTimeoutSeconds');
  }
  if (typed.limits.requestTimeoutSeconds > typed.limits.defaultOperationTimeoutSeconds) {
    malformed('limits.requestTimeoutSeconds');
  }
  return typed;
}

/** Map an HTTP status and error body to this client's discovery code. */
export function discoveryCode(status: number, body: unknown): DiscoveryErrorCode {
  const named =
    isObject(body) && isObject(body['error']) && typeof body['error']['code'] === 'string'
      ? body['error']['code']
      : undefined;
  const known: DiscoveryErrorCode[] = [
    'UNAUTHENTICATED',
    'EXPORT_NOT_FOUND',
    'ACCESS_DENIED',
    'CAPABILITIES_CHANGED',
    'RESOURCE_EXHAUSTED',
    'DEVICE_OFFLINE',
    'BACKEND_UNAVAILABLE',
    'METHOD_NOT_ALLOWED',
    'SUBPROTOCOL_REQUIRED',
    'INVALID_UPGRADE',
  ];
  if (named !== undefined && known.includes(named as DiscoveryErrorCode)) {
    // The endpoint names its own code and a caller branches on it. This is the
    // one route in the relay that answers this vocabulary, so a body carrying
    // one of these is this endpoint answering.
    return named as DiscoveryErrorCode;
  }
  // No usable body — a proxy's own error page, say. Fall back to the status,
  // which is the only thing left that the contract assigns a meaning to.
  switch (status) {
    case 401:
      return 'UNAUTHENTICATED';
    case 403:
      return 'ACCESS_DENIED';
    case 404:
      return 'EXPORT_NOT_FOUND';
    case 405:
      return 'METHOD_NOT_ALLOWED';
    case 409:
      return 'CAPABILITIES_CHANGED';
    case 426:
      return 'SUBPROTOCOL_REQUIRED';
    case 429:
      return 'RESOURCE_EXHAUSTED';
    case 503:
      return 'BACKEND_UNAVAILABLE';
    default:
      return 'BACKEND_UNAVAILABLE';
  }
}
