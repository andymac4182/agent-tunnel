/**
 * The shared client's error shape, and the outcome vocabulary it carries.
 *
 * `docs/filesystem-api.md`: "Shared errors carry `code`, `operation`, virtual
 * `path` when safe, `outcome`, `retryable`, and optional `bytesAcknowledged`."
 */

/**
 * How far a request got.
 *
 * Ordered, and **merged monotonically**: an operation once observed `partial`
 * or `unknown` can never later be reported `not_started`. Gate 1 pins the same
 * ordering on the device side, and the two must not disagree about a word that
 * decides whether a caller may retry.
 */
export type Outcome = 'not_started' | 'failed' | 'partial' | 'unknown';

const ORDER: Record<Outcome, number> = {
  not_started: 0,
  failed: 1,
  partial: 2,
  unknown: 3,
};

/** The stronger of two outcomes. Strength only increases. */
export function mergeOutcome(left: Outcome, right: Outcome): Outcome {
  return ORDER[left] >= ORDER[right] ? left : right;
}

/** The closed errno vocabulary, as the shared client spells it. */
export type FilesystemErrorCode =
  | 'ENOENT'
  | 'EACCES'
  | 'EPERM'
  | 'EROFS'
  | 'EEXIST'
  | 'ENOTDIR'
  | 'EISDIR'
  | 'ENOTEMPTY'
  | 'ELOOP'
  | 'EXDEV'
  | 'ENOTSUP'
  | 'EFBIG'
  | 'ENAMETOOLONG'
  | 'EINVAL';

/** Transport and session failures, kept separate from filesystem absence. */
export type SessionErrorCode =
  | 'SESSION_LOST'
  | 'AUTH_EXPIRED'
  | 'DEVICE_OFFLINE'
  | 'RESOURCE_EXHAUSTED'
  | 'DEADLINE_EXCEEDED'
  | 'ABORTED'
  | 'CAPABILITIES_CHANGED'
  | 'PROTOCOL_VIOLATION';

/** Failures before the upgrade, from the endpoint's own JSON error body. */
export type DiscoveryErrorCode =
  | 'UNAUTHENTICATED'
  | 'EXPORT_NOT_FOUND'
  | 'ACCESS_DENIED'
  | 'CAPABILITIES_CHANGED'
  | 'RESOURCE_EXHAUSTED'
  | 'DEVICE_OFFLINE'
  | 'BACKEND_UNAVAILABLE'
  /** The device's data rotation outlasted the relay's bounded admission hold (M3-15); retryable. */
  | 'ROTATION_FREEZE'
  | 'METHOD_NOT_ALLOWED'
  | 'SUBPROTOCOL_REQUIRED'
  | 'INVALID_UPGRADE'
  | 'MALFORMED_DESCRIPTOR'
  | 'INSECURE_ENDPOINT';

export type ErrorCode = FilesystemErrorCode | SessionErrorCode | DiscoveryErrorCode;

export interface FilesystemErrorFields {
  code: ErrorCode;
  /** The shared-client method, not a 9P opcode. */
  operation: string;
  /**
   * The **virtual** path the caller asked for, when there is one. Never a host
   * path: the client has no way to learn one, because nothing on the wire
   * carries one.
   */
  path?: string | undefined;
  outcome: Outcome;
  retryable: boolean;
  /**
   * A lower bound confirmed by replies. Not proof of final content and not
   * proof of durable bytes — a plain write acknowledgement is not an fsync.
   */
  bytesAcknowledged?: number | undefined;
  /** For a session that closed: the WebSocket close code, when one arrived. */
  closeCode?: number | undefined;
  /**
   * The error this one was built from, when it wraps something that carries no
   * outcome of its own — a refused path, or an exception out of a caller's own
   * chunk source. The wrapper exists so an applied composite always reports an
   * outcome; the cause exists so nothing is lost in doing so.
   */
  cause?: unknown;
}

/**
 * One error type for the whole client.
 *
 * `retryable` is always **false** for a mutation whose outcome is `partial` or
 * `unknown`, whatever the code says: the contract forbids automatic replay of
 * an ambiguous mutation, and an SDK retry wrapper that reads this field must
 * not be handed a reason to try again.
 */
export class FilesystemError extends Error {
  readonly code: ErrorCode;
  readonly operation: string;
  readonly path: string | undefined;
  readonly outcome: Outcome;
  readonly retryable: boolean;
  readonly bytesAcknowledged: number | undefined;
  readonly closeCode: number | undefined;

  constructor(fields: FilesystemErrorFields) {
    // The message carries the code and the operation and nothing else. The
    // path is a *field*, deliberately, so that a caller logging `error.message`
    // cannot put a name into a log line that was never meant to hold one; a
    // caller already knows the path it asked for.
    super(
      `${fields.code} (${fields.operation})`,
      fields.cause === undefined ? undefined : { cause: fields.cause },
    );
    this.name = 'FilesystemError';
    this.code = fields.code;
    this.operation = fields.operation;
    this.path = fields.path;
    this.outcome = fields.outcome;
    this.retryable =
      fields.outcome === 'partial' || fields.outcome === 'unknown' ? false : fields.retryable;
    this.bytesAcknowledged = fields.bytesAcknowledged;
    this.closeCode = fields.closeCode;
  }
}

/** The errno numbers an `Rlerror` carries, to this client's spelling. */
export const ERRNO_TO_CODE = new Map<number, FilesystemErrorCode>([
  [1, 'EPERM'],
  [2, 'ENOENT'],
  [13, 'EACCES'],
  [17, 'EEXIST'],
  [18, 'EXDEV'],
  [20, 'ENOTDIR'],
  [21, 'EISDIR'],
  [22, 'EINVAL'],
  [27, 'EFBIG'],
  [30, 'EROFS'],
  [36, 'ENAMETOOLONG'],
  [39, 'ENOTEMPTY'],
  [40, 'ELOOP'],
  [95, 'ENOTSUP'],
]);

/**
 * The WebSocket close codes `docs/filesystem-api.md` pins, read the way a
 * consumer must read them.
 *
 * "A close code alone cannot encode whether a mutation applied": this maps a
 * code to a *reason*, and nothing here decides an outcome. The outcome comes
 * from the client's own dispatch and reply history — see `classifyOutcome` in
 * `session.ts`.
 */
export function sessionCodeForClose(closeCode: number): SessionErrorCode {
  switch (closeCode) {
    case 1002:
      return 'PROTOCOL_VIOLATION';
    case 1008:
      return 'AUTH_EXPIRED';
    case 1012:
      return 'DEVICE_OFFLINE';
    case 1013:
      return 'RESOURCE_EXHAUSTED';
    case 1011:
      return 'SESSION_LOST';
    default:
      // 1000, 1001, 1006 and anything else: the stream ended and this client
      // was not told why. `SESSION_LOST` is the honest name for that, and
      // inventing a more specific one from a code the profile does not assign
      // would be a claim the wire did not make.
      return 'SESSION_LOST';
  }
}

/** Whether a session-level failure is worth a caller retrying a *fresh* connect. */
export function sessionCodeRetryable(code: SessionErrorCode): boolean {
  // Not one of these retries anything by itself: the client never reconnects
  // behind the caller's back. This says only whether a caller starting again
  // from discovery could succeed.
  return code === 'DEVICE_OFFLINE' || code === 'RESOURCE_EXHAUSTED' || code === 'SESSION_LOST';
}
