/**
 * `@agent-tunnel/client`: the shared TypeScript filesystem client.
 *
 * Implementation gate 6 of `docs/filesystem-api.md`, minus the four native
 * adapters, which are a later chunk and are **not** in this package.
 */

export {
  connectFilesystem,
  fetchDescriptor,
  attachSession,
  MaterializationBudget,
  RemoteFilesystem,
  upgradeRejectionError,
  type ConnectOptions,
  type DirectoryEntry,
  type ReadOptions,
  type Stat,
  type WriteOptions,
} from './filesystem.ts';

export {
  DIALECT,
  GRANT_REVISION_HEADER,
  LIMIT_CEILINGS,
  SCHEMA_VERSION,
  SUBPROTOCOL,
  validateDescriptor,
  type Descriptor,
  type FeatureName,
  type Limits,
  type Operation,
} from './descriptor.ts';

export {
  FilesystemError,
  mergeOutcome,
  sessionCodeForClose,
  type ErrorCode,
  type Outcome,
} from './errors.ts';

export {
  ConsumerSession,
  ROOT_FID,
  classifyOutcome,
  isMutatingRequest,
  type Lifecycle,
  type SessionLimits,
} from './session.ts';

export {
  MAX_COMPONENT_BYTES,
  PathRefusal,
  RESERVED_DEVICE_STEMS,
  validateComponentForJoin,
  validatePath,
  type PathBounds,
  type PathRule,
} from './paths.ts';

export {
  isLoopback,
  requireSecureEndpoint,
  upgrade,
  UpgradeRejected,
  type BinaryTransport,
  type CloseInfo,
} from './websocket.ts';
