/**
 * What every adapter has to do with an outcome, and the one thing none of them
 * can do.
 *
 * `docs/filesystem-api.md` gives the shared client a four-word outcome
 * vocabulary — `not_started`, `failed`, `partial`, `unknown` — and makes two
 * rules about it: an ambiguous mutation is never replayed, and a rejection
 * after a confirmed partial chunk cannot become `not_started`.
 *
 * **No third-party filesystem interface in this gate has that vocabulary.**
 * Files SDK's `FilesError` has five codes and an `applied` flag that means
 * something else; Mastra's `FilesystemError` has a free-form `code` and a
 * `path`; just-bash's `IFileSystem` throws a plain `Error`; AI SDK's `FilesV4`
 * has `warnings` on success and nothing at all on failure. So each adapter
 * chooses a surface, and this module holds what that choice is made **from** —
 * along with the rule the choices share: an adapter never emits a failure its
 * framework would classify as worth retrying.
 *
 * Nothing here renders a path, a name or a byte. `summarize` is what goes into
 * a framework's `message` field, and it carries a code and an operation only.
 */

import { FilesystemError, type Outcome } from '../errors.ts';
import { PathRefusal } from '../paths.ts';

/** The outcome an error carries, when it carries one at all. */
export function outcomeOf(error: unknown): Outcome | undefined {
  return error instanceof FilesystemError ? error.outcome : undefined;
}

/**
 * Whether this failure leaves the export in a state the caller cannot infer.
 *
 * `partial` and `unknown` both mean "something may have happened", and both
 * forbid an automatic second attempt. They are distinguished in the shared
 * client and are **not** distinguishable in any framework surface below; each
 * adapter says so in its own module rather than leaving the merge silent.
 */
export function isAmbiguous(error: unknown): boolean {
  const outcome = outcomeOf(error);
  return outcome === 'partial' || outcome === 'unknown';
}

/**
 * A payload-free one-line description, for a framework field that wants a
 * string.
 *
 * "No path, file name, file content, host path, host identity or credential may
 * appear in a log line, a `Debug` rendering, an error message": a
 * `FilesystemError`'s own message is already `CODE (operation)` for that reason,
 * and a `PathRefusal`'s is a rule name. Anything else contributes only its
 * constructor name — a caller's own exception is the caller's business and its
 * text is not this package's to forward into a framework's logs.
 */
export function summarize(error: unknown): string {
  if (error instanceof FilesystemError) {
    const outcome = error.outcome === 'not_started' ? '' : ` [${error.outcome}]`;
    return `${error.code} (${error.operation})${outcome}`;
  }
  if (error instanceof PathRefusal) {
    return `${error.rule} (path)`;
  }
  if (error instanceof Error) {
    return error.name;
  }
  return 'Error';
}

/** Whether an error is a caller's cancellation rather than a failure. */
export function isAborted(error: unknown): boolean {
  if (error instanceof FilesystemError) {
    return error.code === 'ABORTED';
  }
  return error instanceof Error && error.name === 'AbortError';
}

/**
 * A structured record of one ambiguous mutation, for the side channels that can
 * carry one.
 *
 * Only just-bash has such a channel today (`drainOperationFailures`), but the
 * shape is here rather than there because it is the thing every adapter loses
 * when it maps an outcome onto a framework error, and a second consumer of it
 * should not have to invent the fields again.
 */
export interface OperationFailure {
  /** The adapter method, not a 9P opcode and not a shell command. */
  operation: string;
  /** The shared client's code. */
  code: string;
  /** The **virtual** path, which the caller supplied and already knows. */
  path: string | undefined;
  outcome: Outcome;
  /** Confirmed by replies. A lower bound, never proof of final content. */
  bytesAcknowledged: number | undefined;
}

/** Build a record from whatever the client threw, or `undefined` if it is not ours. */
export function failureRecord(operation: string, error: unknown): OperationFailure | undefined {
  if (!(error instanceof FilesystemError)) {
    return undefined;
  }
  return {
    operation,
    code: error.code,
    path: error.path,
    outcome: error.outcome,
    bytesAcknowledged: error.bytesAcknowledged,
  };
}
