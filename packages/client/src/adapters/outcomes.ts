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

import { FilesystemError, mergeOutcome, type Outcome } from '../errors.ts';
import { PathRefusal } from '../paths.ts';

/**
 * Re-report an adapter composite's failure with the floor its own progress sets.
 *
 * This is `RemoteFilesystem.withCompositeFloor`, one layer up, and it is here
 * for the same reason it is there: **every adapter composes.** `upload`, `copy`
 * and `move` create the key's parent directories before doing their own work,
 * and Mastra's `writeFile` and `copyFile` do the same. A directory made by that
 * `mkdir` is a change to the export, so a later failure of the same adapter call
 * is not `not_started` however the failing step describes itself — and a
 * consumer told `not_started` believes the export untouched.
 *
 * `applied` is decided by what the composite is **known** to have changed:
 * `RemoteFilesystem.mkdir` returns how many directories it created, so a chain
 * that found every component already present sets no floor. It is not inferred
 * from a preliminary `stat`, which would be the exists-then-act race the
 * contract forbids.
 *
 * The merge is gate 1's and only ever strengthens, so a step that ended
 * `unknown` stays `unknown`.
 */
export function withAppliedFloor(
  error: unknown,
  operation: string,
  path: string | undefined,
  applied: boolean,
): unknown {
  if (!applied) {
    // Nothing is known to have changed, so there is no floor to impose and
    // rewriting the error would only lose information.
    return error;
  }
  if (!(error instanceof FilesystemError)) {
    // A `PathRefusal`, or anything else without an outcome field, escaping a
    // call that has already changed the export. A retry wrapper reading
    // `outcome` would see `undefined` and be free to try again.
    return new FilesystemError({
      code: error instanceof Error && error.name === 'AbortError' ? 'ABORTED' : 'EINVAL',
      operation,
      ...(path === undefined ? {} : { path }),
      outcome: 'partial',
      retryable: false,
      cause: error,
    });
  }
  return new FilesystemError({
    code: error.code,
    operation,
    path: error.path ?? path,
    outcome: mergeOutcome(error.outcome, 'partial'),
    retryable: false,
    bytesAcknowledged: error.bytesAcknowledged,
    closeCode: error.closeCode,
    // **The original, not what the original wrapped.** The fields above are
    // copied, so `outcome`, `code` and `bytesAcknowledged` survive either way —
    // but the error being replaced carries its own `operation`, and reaching
    // past it to `error.cause` drops that and leaves a chain with a hole in the
    // middle. `cause` is also where `partial` versus `unknown` survives once a
    // framework has flattened the code, so it is worth keeping whole.
    cause: error,
  });
}

/**
 * Map over values with a bounded number of in-flight operations.
 *
 * The session refuses a request beyond `maxInflightRequests` **locally**, with
 * `RESOURCE_EXHAUSTED`, because the device answers an over-quota request by
 * closing 1013 and a client that sent one would lose every other outstanding
 * request over its own accounting. So an adapter that fans out one call per
 * result — a listing that stats each key — must bound its own fan-out below
 * that quota, or a directory with more keys than the quota can never produce a
 * page at all.
 */
export async function mapBounded<T, R>(
  values: readonly T[],
  concurrency: number,
  run: (value: T, index: number) => Promise<R>,
): Promise<R[]> {
  const out = new Array<R>(values.length);
  let next = 0;
  // **The first failure stops the rest.** `Promise.all` rejects as soon as one
  // worker throws, so without this the others keep pulling from `next` and keep
  // sending requests — spending the very quota the bound exists to protect,
  // after the caller already holds an error, and with their own failures
  // swallowed because nothing is awaiting them any more. A run that failed on
  // its fourth item was observed dispatching sixteen and then nineteen.
  let failed = false;
  const worker = async (): Promise<void> => {
    for (;;) {
      if (failed) {
        return;
      }
      const index = next;
      next += 1;
      if (index >= values.length) {
        return;
      }
      try {
        out[index] = await run(values[index] as T, index);
      } catch (error) {
        failed = true;
        throw error;
      }
    }
  };
  const workers = Math.max(1, Math.min(concurrency, values.length));
  await Promise.all(Array.from({ length: workers }, worker));
  return out;
}

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
