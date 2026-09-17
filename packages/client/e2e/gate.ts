/**
 * The gate-6 end-to-end driver: `@agent-tunnel/client` against **actual relay
 * and device sockets**.
 *
 * This file is not part of `npm test` and has no assertions of its own beyond
 * the ones needed to keep going. It is a **child process driven by the Rust
 * gate** in `crates/tunnel-test-harness/src/production_cluster/fs_client_e2e.rs`:
 * the harness stands up the three-relay production cluster, a real Redis
 * catalog and a real device connector serving filesystem exports, writes a plan
 * file, spawns `node` on this script, and validates the structured report this
 * script prints. Every judgement about whether the run passed is taken in Rust,
 * against evidence that is scalars and closed labels — so a driver that decided
 * for itself what "passed" means could not smuggle a verdict past the
 * validator.
 *
 * **Why a child process.** The alternative was to embed a JavaScript runtime in
 * the harness or to re-implement the client's behaviour in Rust, and both give
 * up the one thing gate 6 says it must prove: that *the published package*
 * interoperates with the product's endpoint. `node` running this package's own
 * `src/` is the product under test; a process boundary is the only shape in
 * which the harness can own the cluster and the package can own the client.
 * The two halves talk over three channels, each chosen for what it carries:
 *
 * * **argv[1]** is a plan file — endpoints, one consumer token, and the shape
 *   of the synthetic content each case expects. It is a file rather than an
 *   argument vector because a token must not appear in a process listing.
 * * **stdout** is newline-delimited JSON. Exactly one `report` line ends the
 *   run; a `descriptor` line is the rendezvous below.
 * * **stdin** carries one `go` line, which is how the grant-revision case is
 *   made a race the harness wins rather than a sleep.
 *
 * Nothing here prints a path, a file name, a byte of content or the token: the
 * report is counters, closed labels and booleans, and diagnostics go to stderr
 * as bounded identifiers.
 */

import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';

import {
  ConsumerSession,
  FilesystemError,
  RemoteFilesystem,
  UpgradeRejected,
  attachSession,
  connectFilesystem,
  fetchDescriptor,
  upgrade,
  upgradeRejectionError,
  type BinaryTransport,
  type Descriptor,
} from '../src/index.ts';
import { GRANT_REVISION_HEADER, SUBPROTOCOL } from '../src/descriptor.ts';
import { MESSAGE_TYPES } from '../src/ninep/constants.ts';
import { TunnelMastraFilesystem, type MastraErrorClasses } from '../src/adapters/mastra.ts';

/* ------------------------------------------------------------------ *
 * The plan, and the synthetic content both sides generate
 * ------------------------------------------------------------------ */

interface Plan {
  endpoints: {
    readWrite: string;
    readOnly: string;
    revision: string;
    unknown: string;
    adapter: string;
  };
  token: string;
  read: { path: string; bytes: number; checksum: string };
  write: { path: string; bytes: number };
  listing: { path: string; names: string[] };
  readOnlyCase: { readPath: string; bytes: number; writePath: string; renameTo: string };
  unknownCase: { path: string; writes: number; chunkBytes: number };
  adapterCase: { readPath: string; bytes: number; writePath: string; writeBytes: number; listing: string[] };
}

/**
 * Deterministic synthetic content: byte `i` is `i % 251`.
 *
 * The same rule the Rust side uses. 251 is prime and below 256, so the pattern
 * does not align with any power of two the transport uses and a block that
 * moved, repeated or vanished changes the checksum.
 */
function syntheticBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let index = 0; index < length; index += 1) {
    bytes[index] = index % 251;
  }
  return bytes;
}

/** FNV-1a over 64 bits, the same constants the Rust side uses. */
function fnv1a(bytes: Uint8Array): bigint {
  const mask = 0xffff_ffff_ffff_ffffn;
  let hash = 0xcbf2_9ce4_8422_2325n;
  for (const byte of bytes) {
    hash = (hash ^ BigInt(byte)) & mask;
    hash = (hash * 0x0000_0100_0000_01b3n) & mask;
  }
  return hash;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) {
    return false;
  }
  for (let index = 0; index < left.byteLength; index += 1) {
    if (left[index] !== right[index]) {
      return false;
    }
  }
  return true;
}

/* ------------------------------------------------------------------ *
 * The report
 * ------------------------------------------------------------------ */

/**
 * What the Rust validator reads. Every field is a scalar, a closed label or a
 * count: no path, no name, no content and no credential is representable.
 */
interface Report {
  // (a) TLS and the descriptor, read by the real client over a verified socket.
  /**
   * Whether this process was **able** to skip verification.
   *
   * `NODE_TLS_REJECT_UNAUTHORIZED=0` turns node's certificate verification off
   * process-wide, and an earlier round of this gate passed with it set: the
   * driver simply asserted `tlsVerified = true` once a connect resolved, which
   * is true of an unverified connect too. The harness now removes the variable
   * and refuses to run when its own environment sets it, and the driver reports
   * what it actually sees so the validator can pin it unset rather than trust
   * that it was.
   */
  nodeTlsRejectUnauthorized: string;
  /** The filesystem path this driver resolved for the client under test. */
  clientModulePath: string;
  /** Whether the composed public entry point was driven, not only its pieces. */
  publicEntryPointUsed: boolean;
  descriptorSchemaVersion: string;
  descriptorSubprotocol: string;
  descriptorDialect: string;
  descriptorGrantRevisionPresent: boolean;
  descriptorOperations: string[];
  descriptorReadOnly: boolean;
  descriptorAvailability: string;
  // (b) an unauthenticated descriptor read.
  unauthenticatedCode: string;
  unauthenticatedOutcome: string;
  // (c) the grant-revision header, against a revision that really moved.
  revisionUpgradeStatus: number;
  revisionUpgradeCode: string;
  revisionUpgradeOutcome: string;
  revisionUpgradeRetryable: boolean;
  // (d) the authenticated upgrade and its subprotocol.
  selectedSubprotocol: string;
  negotiatedMsize: number;
  sessionLifecycle: string;
  // (e) a checksummed read spanning many messages.
  readBytes: number;
  readChecksumMatches: boolean;
  readMessages: number;
  // (f) a checksummed write spanning many messages.
  writeBytes: number;
  writeMessages: number;
  writeAcknowledgements: number;
  // (g) a directory listing.
  listingNamesObserved: number;
  listingEveryNameExactlyOnce: boolean;
  // (h) a read-only grant refusing mutations, at both layers.
  readOnlyReadMatches: boolean;
  readOnlyRootReadOnly: boolean;
  readOnlyAdvertisesNoMutation: boolean;
  /** Through the client's own entry points: refused locally, never sent. */
  readOnlyClientCodes: string[];
  readOnlyClientOutcomes: string[];
  /** Through the raw session, which is what a caller speaking 9P directly does. */
  readOnlyDeviceCreateCode: string;
  readOnlyDeviceMkdirCode: string;
  readOnlyDeviceUnlinkCode: string;
  readOnlyDeviceOpenWriteCode: string;
  readOnlyDeviceOutcomes: string[];
  readOnlyAnyRetryable: boolean;
  // (i) an outcome this client classifies `unknown`.
  unknownRequests: number;
  unknownClassifiedUnknown: number;
  unknownAnyRetryable: boolean;
  unknownClientAcknowledgedBytes: number;
  unknownCloseCodes: number[];
  // (j) one adapter, not only the raw client.
  adapterName: string;
  adapterReadMatches: boolean;
  adapterWriteBytes: number;
  adapterListingNames: number;
  adapterStatSizeMatches: boolean;
  adapterAppendRefused: string;
  // Anything the driver could not carry out. Empty on a clean run; the
  // validator refuses a report that names one, so a case that silently did
  // not run cannot be read as a case that passed.
  failures: string[];
}

function blankReport(): Report {
  return {
    nodeTlsRejectUnauthorized: '',
    clientModulePath: '',
    publicEntryPointUsed: false,
    descriptorSchemaVersion: '',
    descriptorSubprotocol: '',
    descriptorDialect: '',
    descriptorGrantRevisionPresent: false,
    descriptorOperations: [],
    descriptorReadOnly: true,
    descriptorAvailability: '',
    unauthenticatedCode: '',
    unauthenticatedOutcome: '',
    revisionUpgradeStatus: 0,
    revisionUpgradeCode: '',
    revisionUpgradeOutcome: '',
    revisionUpgradeRetryable: true,
    selectedSubprotocol: '',
    negotiatedMsize: 0,
    sessionLifecycle: '',
    readBytes: 0,
    readChecksumMatches: false,
    readMessages: 0,
    writeBytes: 0,
    writeMessages: 0,
    writeAcknowledgements: 0,
    listingNamesObserved: 0,
    listingEveryNameExactlyOnce: false,
    readOnlyReadMatches: false,
    readOnlyRootReadOnly: false,
    readOnlyAdvertisesNoMutation: false,
    readOnlyClientCodes: [],
    readOnlyClientOutcomes: [],
    readOnlyDeviceCreateCode: '',
    readOnlyDeviceMkdirCode: '',
    readOnlyDeviceUnlinkCode: '',
    readOnlyDeviceOpenWriteCode: '',
    readOnlyDeviceOutcomes: [],
    readOnlyAnyRetryable: false,
    unknownRequests: 0,
    unknownClassifiedUnknown: 0,
    unknownAnyRetryable: false,
    unknownClientAcknowledgedBytes: 0,
    unknownCloseCodes: [],
    adapterName: '',
    adapterReadMatches: false,
    adapterWriteBytes: 0,
    adapterListingNames: 0,
    adapterStatSizeMatches: false,
    adapterAppendRefused: '',
    failures: [],
  };
}

/** A `FilesystemError`'s code, or a closed label naming what else it was. */
function codeOf(error: unknown): string {
  return error instanceof FilesystemError ? error.code : `NOT_A_FILESYSTEM_ERROR:${(error as Error)?.name ?? 'unknown'}`;
}

function outcomeOf(error: unknown): string {
  return error instanceof FilesystemError ? error.outcome : '';
}

function retryableOf(error: unknown): boolean {
  return error instanceof FilesystemError ? error.retryable : false;
}

/* ------------------------------------------------------------------ *
 * The rendezvous
 * ------------------------------------------------------------------ */

function emit(line: unknown): void {
  process.stdout.write(`${JSON.stringify(line)}\n`);
}

/**
 * The last line, written and **flushed** before the process may exit.
 *
 * `process.stdout.write` to a pipe is asynchronous once the buffer fills, and
 * the report is the largest line this driver produces; exiting on the next tick
 * relied on it fitting in the pipe buffer.
 */
function emitFinal(line: unknown): Promise<void> {
  return new Promise((resolve) => {
    process.stdout.write(`${JSON.stringify(line)}\n`, () => resolve());
  });
}

/**
 * Wait for one `go` line from the harness.
 *
 * `next()` rather than `for await`, deliberately: a `for await` that leaves its
 * loop early calls the iterator's `return()`, which **closes** it — so the
 * first rendezvous would consume stdin for the whole run and the second would
 * see an iterator that was already done and report the harness as having
 * closed stdin. There are two rendezvous, and they share one iterator.
 */
/**
 * Run one case between a pair of rendezvous, and **always** close the pair.
 *
 * The closing event is emitted from a `finally`, because a case that throws
 * between the two leaves the harness blocked on a rendezvous that never
 * arrives — which it can only report as a timeout, burying the failure the
 * report was about to carry. The harness treats the closing event as "this
 * case is over", not as "this case succeeded".
 */
async function bracket(
  name: string,
  lines: AsyncIterableIterator<string>,
  body: () => Promise<void>,
): Promise<void> {
  emit({ event: `${name}-start` });
  await awaitGo(lines);
  try {
    await body();
  } finally {
    // The closing rendezvous must not be able to *replace* the body's error.
    // A `finally` that throws discards whatever was propagating through it, so
    // a harness that had closed stdin would turn "the read-only case failed
    // with EPERM" into "stdin closed" — the same class of burying the `finally`
    // itself was added to prevent. Today the harness never closes stdin early,
    // and a rule that is only true because of what the peer happens to do is
    // not a rule.
    emit({ event: `${name}-done` });
    try {
      await awaitGo(lines);
    } catch (error) {
      process.stderr.write(
        `gate6-e2e: the ${name} rendezvous did not close: ${(error as Error)?.name ?? 'unknown'}\n`,
      );
    }
  }
}

async function awaitGo(lines: AsyncIterableIterator<string>): Promise<void> {
  for (;;) {
    const next = await lines.next();
    if (next.done === true) {
      throw new Error('the harness closed stdin without releasing the rendezvous');
    }
    if (next.value.trim() === 'go') {
      return;
    }
  }
}

/* ------------------------------------------------------------------ *
 * Cases
 * ------------------------------------------------------------------ */

const token = (plan: Plan) => () => plan.token;

interface RawClient {
  remote: RemoteFilesystem;
  session: ConsumerSession;
  descriptor: Descriptor;
  /** Frames this session actually sent and received, counted by opcode. */
  frames: FrameCounts;
}

/**
 * Frames counted at the transport, by the opcode byte of the 9P header.
 *
 * A 9P message is `size[4] type[1] tag[2] …`, so the opcode is byte 4 of every
 * complete message — and one complete message is exactly what a consumer
 * binary WebSocket message carries in this profile, which is why counting here
 * is counting messages and not counting fragments.
 */
class FrameCounts {
  private readonly sent = new Map<number, number>();
  private readonly received = new Map<number, number>();

  note(bytes: Uint8Array, into: Map<number, number>): void {
    if (bytes.byteLength < 5) {
      return;
    }
    const opcode = bytes[4] as number;
    into.set(opcode, (into.get(opcode) ?? 0) + 1);
  }

  noteSent(bytes: Uint8Array): void {
    this.note(bytes, this.sent);
  }

  noteReceived(bytes: Uint8Array): void {
    this.note(bytes, this.received);
  }

  sentCount(opcode: number): number {
    return this.sent.get(opcode) ?? 0;
  }

  receivedCount(opcode: number): number {
    return this.received.get(opcode) ?? 0;
  }
}

/**
 * Connect, keeping the session.
 *
 * `connectFilesystem` owns its `ConsumerSession` privately, which is right for
 * an application and wrong for two of these cases: one has to issue primitives
 * the client would refuse locally because they are not advertised, and the
 * other has to issue writes without awaiting them. Both go through the same
 * exported pieces `connectFilesystem` composes — `fetchDescriptor`, `upgrade`,
 * `ConsumerSession`, `attachSession` — so nothing here is a reimplementation of
 * the client; it is the client with one more reference held.
 */
async function connectRaw(endpoint: string, plan: Plan): Promise<RawClient> {
  const descriptor = await fetchDescriptor({ endpoint, token: token(plan) });
  const frames = new FrameCounts();
  let session: ConsumerSession | undefined;
  const socket: BinaryTransport = await upgrade({
    url: new URL(endpoint),
    subprotocol: SUBPROTOCOL,
    headers: {
      Authorization: `Bearer ${plan.token}`,
      [GRANT_REVISION_HEADER]: descriptor.grantRevision,
    },
    maxMessageBytes: descriptor.limits.maxMessageBytes,
    allowInsecureLoopback: false,
    timeoutMs: descriptor.limits.requestTimeoutSeconds * 1000,
    handlers: {
      onMessage: (bytes) => {
        frames.noteReceived(bytes);
        session?.onMessage(bytes);
      },
      onClose: (info) => session?.onClose(info),
    },
  });
  // An explicit delegate rather than a spread: `isOpen` is a getter, and
  // copying it would freeze the value the session reads.
  const transport: BinaryTransport = {
    get isOpen() {
      return socket.isOpen;
    },
    send(bytes) {
      frames.noteSent(bytes);
      socket.send(bytes);
    },
    close(code, reason) {
      socket.close(code, reason);
    },
  };
  session = new ConsumerSession(transport, {
    msize: descriptor.limits.maxMessageBytes,
    maxInflightRequests: descriptor.limits.maxInflightRequests,
    maxFids: descriptor.limits.maxFids,
    requestTimeoutMs: descriptor.limits.requestTimeoutSeconds * 1000,
  });
  const remote = await attachSession(descriptor, transport, session);
  return { remote, session, descriptor, frames };
}

/**
 * (b) An unauthenticated descriptor read.
 *
 * The same endpoint and the same client, with a token the issuer never signed:
 * `401 UNAUTHENTICATED` through the client's own discovery vocabulary.
 */
async function unauthenticatedCase(plan: Plan, report: Report): Promise<void> {
  try {
    await fetchDescriptor({
      endpoint: plan.endpoints.readWrite,
      token: () => 'not-a-signed-consumer-token',
    });
    report.failures.push('an unsigned token was admitted');
  } catch (error) {
    report.unauthenticatedCode = codeOf(error);
    report.unauthenticatedOutcome = outcomeOf(error);
  }
}

/**
 * (c) The `grantRevision` header, against a revision that really moved.
 *
 * The client fetches a descriptor and then upgrades at the same URL carrying
 * that descriptor's revision. This case makes the revision move **between** the
 * two, in the authoritative catalog, and the relay must refuse the upgrade with
 * `409 CAPABILITIES_CHANGED` — which is the only way to observe, from outside,
 * that the header was sent at all.
 *
 * The move is the harness's to make, so this is a rendezvous rather than a
 * sleep: the descriptor is fetched, its revision is announced, and the upgrade
 * waits for the harness to say the catalog has moved and a fresh descriptor
 * reports it.
 */
async function revisionCase(
  plan: Plan,
  report: Report,
  lines: AsyncIterableIterator<string>,
): Promise<void> {
  const descriptor = await fetchDescriptor({
    endpoint: plan.endpoints.revision,
    token: token(plan),
  });
  emit({ event: 'descriptor', revision: descriptor.grantRevision });
  await awaitGo(lines);
  // `connectFilesystem` fetches its own descriptor, so it could never carry a
  // superseded revision; this case therefore drives the upgrade directly with
  // the revision a consumer read a moment ago, which is precisely the cached
  // descriptor the contract says authorizes nothing.
  try {
    const transport = await upgrade({
      url: new URL(plan.endpoints.revision),
      subprotocol: SUBPROTOCOL,
      headers: {
        Authorization: `Bearer ${plan.token}`,
        [GRANT_REVISION_HEADER]: descriptor.grantRevision,
      },
      maxMessageBytes: descriptor.limits.maxMessageBytes,
      allowInsecureLoopback: false,
      timeoutMs: descriptor.limits.requestTimeoutSeconds * 1000,
      handlers: { onMessage: () => {}, onClose: () => {} },
    });
    transport.close(1000, 'superseded-admitted');
    report.failures.push('a superseded grant revision was admitted at the upgrade');
  } catch (error) {
    if (!(error instanceof UpgradeRejected)) {
      throw error;
    }
    // The **client's own** mapping from a refused upgrade to its error
    // vocabulary, not this driver's reading of the status line.
    // `connectFilesystem` cannot be used for this case — it always fetches a
    // fresh descriptor, so it could never carry a superseded revision — and a
    // driver that hard-coded `not_started` here would be asserting a constant
    // it had written itself. `upgradeRejectionError` is the exact function
    // `connectFilesystem` calls on this path, exported for that reason.
    const mapped = upgradeRejectionError(error);
    report.revisionUpgradeStatus = error.status;
    report.revisionUpgradeCode = mapped.code;
    report.revisionUpgradeOutcome = mapped.outcome;
    report.revisionUpgradeRetryable = mapped.retryable;
  }
}

/**
 * (a), (d), (e), (f), (g): one connected client on the writable export.
 *
 * The descriptor, the upgrade with its selected subprotocol, a checksummed read
 * spanning many `Rread` messages, a checksummed write spanning many `Twrite`
 * messages, and a directory listing.
 */
async function readWriteCase(plan: Plan, report: Report): Promise<void> {
  // `connectRaw` rather than `connectFilesystem`, for one reason: the message
  // counts below have to be **counted**, and that needs the transport. It runs
  // the same exported pieces `connectFilesystem` composes, in the same order.
  // The composed entry point itself is driven by the adapter case, which
  // records that it was.
  const { remote, frames } = await connectRaw(plan.endpoints.readWrite, plan);
  try {
    const descriptor = remote.descriptor;
    report.descriptorSchemaVersion = descriptor.schemaVersion;
    report.descriptorSubprotocol = descriptor.transport.subprotocol;
    report.descriptorDialect = descriptor.transport.dialect;
    report.descriptorGrantRevisionPresent = descriptor.grantRevision.length > 0;
    report.descriptorOperations = [...descriptor.operations].sort();
    report.descriptorReadOnly = descriptor.root.readOnly;
    report.descriptorAvailability = descriptor.availability;
    report.selectedSubprotocol = descriptor.transport.subprotocol;
    report.negotiatedMsize = remote.msize;
    report.sessionLifecycle = remote.state;

    // (e) The checksummed read. The message count is **counted at the
    // transport**, by the opcode byte of each complete message the socket
    // delivered: one consumer binary message is one complete 9P message in this
    // profile, so counting `Rread` opcodes is counting `Rread` messages. An
    // earlier round computed `ceil(bytes / maxCount)` here, which would have
    // reported "more than four messages" for any chunking at all — including a
    // chunking that never happened.
    const readFramesBefore = frames.receivedCount(MESSAGE_TYPES.Rread);
    const bytes = await remote.readFile(plan.read.path);
    report.readBytes = bytes.byteLength;
    report.readChecksumMatches = fnv1a(bytes) === BigInt(plan.read.checksum);
    report.readMessages = frames.receivedCount(MESSAGE_TYPES.Rread) - readFramesBefore;

    // (f) The checksummed write, handed over as a stream of chunks so the
    // client's own `Twrite` chunking is what spans the messages.
    const source = syntheticBytes(plan.write.bytes);
    const chunkBytes = 65_536;
    const chunks: Uint8Array[] = [];
    for (let at = 0; at < source.byteLength; at += chunkBytes) {
      chunks.push(source.subarray(at, Math.min(at + chunkBytes, source.byteLength)));
    }
    const writeFramesBefore = frames.sentCount(MESSAGE_TYPES.Twrite);
    await remote.writeStream(plan.write.path, chunks);
    report.writeBytes = source.byteLength;
    // Counted at the transport too, on the way out: `Twrite` opcodes actually
    // handed to `send`, not a division.
    report.writeMessages = frames.sentCount(MESSAGE_TYPES.Twrite) - writeFramesBefore;
    // And the replies to them, so a `Twrite` count that did not produce a
    // matching `Rwrite` count could not be read as a completed write.
    report.writeAcknowledgements = frames.receivedCount(MESSAGE_TYPES.Rwrite);

    // (g) The listing.
    const names: string[] = [];
    for await (const entry of remote.readDirectory(plan.listing.path)) {
      names.push(entry.name);
    }
    report.listingNamesObserved = names.length;
    const expected = [...plan.listing.names].sort();
    const observed = [...names].sort();
    report.listingEveryNameExactlyOnce =
      observed.length === expected.length && observed.every((name, index) => name === expected[index]);
  } finally {
    await remote.close();
  }
}

/**
 * (h) A read-only grant refusing mutations.
 *
 * The descriptor's `root.readOnly` is derived from the grant, and this client
 * refuses an unadvertised operation locally — but the refusal that matters is
 * the **device's**, so each mutation is attempted through the ordinary entry
 * point and the code and outcome it produced are recorded whichever layer took
 * it. The harness checks the export is byte-for-byte unchanged afterwards.
 */
async function readOnlyCase(
  plan: Plan,
  report: Report,
  lines: AsyncIterableIterator<string>,
): Promise<void> {
  // The harness reads the device's ledger on both sides of this case, so it
  // can say what the device believes happened while the client is reporting
  // what the wire let it conclude. `bracket` emits the closing event from a
  // `finally`: a case that threw between the two used to leave the harness
  // waiting on a rendezvous that would never arrive, which it reported as a
  // device that never recorded an exchange — burying the real failure the
  // report was carrying.
  await bracket('read-only', lines, () => readOnlyBody(plan, report));
}

async function readOnlyBody(plan: Plan, report: Report): Promise<void> {
  const { remote, session, descriptor } = await connectRaw(plan.endpoints.readOnly, plan);
  try {
    report.readOnlyRootReadOnly = descriptor.root.readOnly;
    report.readOnlyAdvertisesNoMutation = !descriptor.operations.some((operation) =>
      ['writeFile', 'writeStream', 'appendFile', 'mkdir', 'remove', 'rename', 'copy'].includes(operation),
    );
    const bytes = await remote.readFile(plan.readOnlyCase.readPath);
    report.readOnlyReadMatches = equalBytes(bytes, syntheticBytes(plan.readOnlyCase.bytes));

    // Through the client's own entry points. The refusal here is **local** —
    // an operation the descriptor does not advertise — and that is worth
    // recording separately from the device's, because it is the statement that
    // a caller's mistake never reaches the socket, not a statement about
    // enforcement.
    const attempts: [string, () => Promise<unknown>][] = [
      ['write', () => remote.writeFile(plan.readOnlyCase.writePath, syntheticBytes(32))],
      ['mkdir', () => remote.mkdir(plan.readOnlyCase.writePath)],
      ['remove', () => remote.remove(plan.readOnlyCase.readPath)],
      ['rename', () => remote.rename(plan.readOnlyCase.readPath, plan.readOnlyCase.renameTo)],
    ];
    for (const [name, attempt] of attempts) {
      try {
        await attempt();
        report.failures.push(`a read-only grant admitted ${name}`);
        report.readOnlyClientCodes.push('ADMITTED');
        report.readOnlyClientOutcomes.push('unknown');
      } catch (error) {
        report.readOnlyClientCodes.push(codeOf(error));
        report.readOnlyClientOutcomes.push(outcomeOf(error));
        if (retryableOf(error)) {
          report.readOnlyAnyRetryable = true;
        }
      }
    }

    // Through the raw session, which is what "a custom 9P client receives the
    // same restrictions" means: the local check is bypassed entirely and the
    // device is the only thing left to refuse.
    const name = plan.readOnlyCase.writePath.slice(1);
    const parent = session.allocateFid();
    const walked = await session.request({ kind: 'Twalk', tag: 0, fid: 0, newfid: parent, wnames: [] });
    if (walked.kind !== 'Rwalk') {
      throw new Error('the root clone was not answered with an Rwalk');
    }
    const primitives: [string, () => Promise<unknown>, (code: string) => void][] = [
      [
        'Tlcreate',
        () =>
          session.request({ kind: 'Tlcreate', tag: 0, fid: parent, name, flags: 1, mode: 0o644, gid: 0 }),
        (code) => {
          report.readOnlyDeviceCreateCode = code;
        },
      ],
      [
        'Tmkdir',
        () => session.request({ kind: 'Tmkdir', tag: 0, dfid: parent, name, mode: 0o755, gid: 0 }),
        (code) => {
          report.readOnlyDeviceMkdirCode = code;
        },
      ],
      [
        'Tunlinkat',
        () =>
          session.request({
            kind: 'Tunlinkat',
            tag: 0,
            dirfid: parent,
            name: plan.readOnlyCase.readPath.slice(1),
            flags: 0,
          }),
        (code) => {
          report.readOnlyDeviceUnlinkCode = code;
        },
      ],
    ];
    for (const [label, attempt, record] of primitives) {
      try {
        await attempt();
        report.failures.push(`a read-only grant admitted ${label}`);
        record('ADMITTED');
        report.readOnlyDeviceOutcomes.push('unknown');
      } catch (error) {
        record(codeOf(error));
        report.readOnlyDeviceOutcomes.push(outcomeOf(error));
        if (retryableOf(error)) {
          report.readOnlyAnyRetryable = true;
        }
      }
    }
    // A writable open on a file that exists, which is the mutating **flag**
    // rather than a mutating opcode.
    const target = session.allocateFid();
    const toFile = await session.request({
      kind: 'Twalk',
      tag: 0,
      fid: 0,
      newfid: target,
      wnames: [plan.readOnlyCase.readPath.slice(1)],
    });
    if (toFile.kind !== 'Rwalk') {
      throw new Error('the walk to the read-only file was not answered with an Rwalk');
    }
    try {
      await session.request({ kind: 'Tlopen', tag: 0, fid: target, flags: 1 });
      report.failures.push('a read-only grant admitted a writable open');
      report.readOnlyDeviceOpenWriteCode = 'ADMITTED';
      report.readOnlyDeviceOutcomes.push('unknown');
    } catch (error) {
      report.readOnlyDeviceOpenWriteCode = codeOf(error);
      report.readOnlyDeviceOutcomes.push(outcomeOf(error));
      if (retryableOf(error)) {
        report.readOnlyAnyRetryable = true;
      }
    }
  } finally {
    await remote.close();
  }
}

/**
 * (i) An outcome this client classifies `unknown`.
 *
 * Gate 5 named this obligation for this side: "there is no wire field for an
 * outcome", so a dispatched mutation with no reply is `unknown` and the device's
 * own ledger is the only place the truth lives. Making that reachable needs a
 * mutation that is genuinely **dispatched and unanswered**, and this is the one
 * arrangement in which that is a fact rather than a race: the writes are issued
 * without awaiting — `ConsumerSession.sendRaw` encodes and sends inside the
 * promise executor, so every one of them is on the transport when the call
 * returns — and the client is closed in the **same synchronous turn**, before
 * the event loop can deliver a single reply.
 *
 * It uses the exported session directly rather than `writeStream`, which awaits
 * each `Rwrite` before sending the next and therefore never has more than one
 * write outstanding. Everything under it is the same product code
 * `connectFilesystem` runs.
 */
async function unknownCase(
  plan: Plan,
  report: Report,
  lines: AsyncIterableIterator<string>,
): Promise<void> {
  // Bracketed, so the harness's ledger reading happens whether this case
  // succeeds or throws. Its opening rendezvous costs nothing — no exchange has
  // happened yet — and its closing one is what the ledger delta is measured to.
  await bracket('unknown', lines, () => unknownBody(plan, report));
}

async function unknownBody(plan: Plan, report: Report): Promise<void> {
  const { remote, session: live } = await connectRaw(plan.endpoints.unknown, plan);
  try {
    // Create the file through the ordinary primitives, and await those: the
    // case is about writes with no reply, not about a create with none.
    const parent = live.allocateFid();
    const walked = await live.request({ kind: 'Twalk', tag: 0, fid: 0, newfid: parent, wnames: [] });
    if (walked.kind !== 'Rwalk') {
      throw new Error('the root clone was not answered with an Rwalk');
    }
    const name = plan.unknownCase.path.slice(1);
    const created = await live.request({
      kind: 'Tlcreate',
      tag: 0,
      fid: parent,
      name,
      flags: 1, // O_WRONLY
      mode: 0o644,
      gid: 0,
    });
    if (created.kind !== 'Rlcreate') {
      throw new Error('the create was not answered with an Rlcreate');
    }

    const chunk = syntheticBytes(plan.unknownCase.chunkBytes);
    const pending: Promise<unknown>[] = [];
    const outcomes: string[] = [];
    const closeCodes = new Set<number>();
    let acknowledged = 0;
    let retryable = false;
    for (let index = 0; index < plan.unknownCase.writes; index += 1) {
      const at = BigInt(index * plan.unknownCase.chunkBytes);
      pending.push(
        live
          .request({ kind: 'Twrite', tag: 0, fid: parent, offset: at, data: chunk })
          .then(
            () => {
              outcomes.push('answered');
            },
            (error: unknown) => {
              outcomes.push(outcomeOf(error));
              acknowledged += (error as FilesystemError).bytesAcknowledged ?? 0;
              if (retryableOf(error)) {
                retryable = true;
              }
              const close = (error as FilesystemError).closeCode;
              if (close !== undefined) {
                closeCodes.add(close);
              }
            },
          ),
      );
    }
    // Synchronously, in the same turn the writes were issued in: no reply can
    // have been read, so every one of them is dispatched and unanswered.
    live.close();
    await Promise.all(pending);
    report.unknownRequests = outcomes.length;
    report.unknownClassifiedUnknown = outcomes.filter((outcome) => outcome === 'unknown').length;
    report.unknownAnyRetryable = retryable;
    report.unknownClientAcknowledgedBytes = acknowledged;
    report.unknownCloseCodes = [...closeCodes].sort((left, right) => left - right);
  } finally {
    await remote.close();
  }
}

/**
 * (j) One adapter, not only the raw client, end to end.
 *
 * The Mastra adapter, because it is one of the two whose framework reaches it
 * as **injected error classes** rather than as a runtime import — so the socket
 * under it can be the real one without an installed framework in the harness's
 * environment. What is new here is the socket: task row M4-14 registered this
 * adapter with its framework's own consumer object against a loopback harness,
 * and this run drives it against `crates/tunnel-relay` and
 * `crates/tunnel-fs-provider`. The error classes are stand-ins with the same
 * constructor shapes the offline adapter suites already use, and the residue
 * says so rather than implying the framework itself ran here.
 */
async function adapterCase(plan: Plan, report: Report): Promise<void> {
  // Stand-in framework classes, the same shape the offline adapter suites use.
  // A parameter property would not survive type stripping, so the field is
  // declared and assigned.
  class Stand extends Error {
    readonly label: string;

    constructor(label: string, ...rest: unknown[]) {
      super(`${label}:${rest.length}`);
      this.label = label;
      this.name = label;
    }
  }
  const errors: MastraErrorClasses = {
    FilesystemError: class extends Stand {
      constructor(message: string, code: string, path: string) {
        super('FilesystemError', message, code, path);
      }
    },
    FileNotFoundError: class extends Stand {
      constructor(path: string) {
        super('FileNotFoundError', path);
      }
    },
    DirectoryNotFoundError: class extends Stand {
      constructor(path: string) {
        super('DirectoryNotFoundError', path);
      }
    },
    FileExistsError: class extends Stand {
      constructor(path: string) {
        super('FileExistsError', path);
      }
    },
    IsDirectoryError: class extends Stand {
      constructor(path: string) {
        super('IsDirectoryError', path);
      }
    },
    NotDirectoryError: class extends Stand {
      constructor(path: string) {
        super('NotDirectoryError', path);
      }
    },
    DirectoryNotEmptyError: class extends Stand {
      constructor(path: string) {
        super('DirectoryNotEmptyError', path);
      }
    },
    PermissionError: class extends Stand {
      constructor(path: string, operation: string) {
        super('PermissionError', path, operation);
      }
    },
    StaleFileError: class extends Stand {
      constructor(path: string, expected: Date, actual: Date) {
        super('StaleFileError', path, expected, actual);
      }
    },
  };

  const remote = await connectFilesystem({
    endpoint: plan.endpoints.adapter,
    token: token(plan),
  });
  // `connectFilesystem` itself, not its pieces: the read-write case has to hold
  // the transport to count frames, so this is where the composed public entry
  // point is driven against the real endpoint, and the report says so.
  report.publicEntryPointUsed = true;
  const filesystem = new TunnelMastraFilesystem({ remote, errors });
  try {
    await filesystem.init();
    report.adapterName = 'mastra';

    const read = await filesystem.readFile(plan.adapterCase.readPath);
    const bytes = typeof read === 'string' ? new TextEncoder().encode(read) : new Uint8Array(read);
    report.adapterReadMatches = equalBytes(bytes, syntheticBytes(plan.adapterCase.bytes));

    await filesystem.writeFile(
      plan.adapterCase.writePath,
      Buffer.from(syntheticBytes(plan.adapterCase.writeBytes)),
    );
    report.adapterWriteBytes = plan.adapterCase.writeBytes;

    const entries = await filesystem.readdir('/');
    const expected = [...plan.adapterCase.listing].sort();
    const observed = entries.map((entry) => entry.name).sort();
    report.adapterListingNames =
      observed.length === expected.length && observed.every((name, index) => name === expected[index])
        ? observed.length
        : -1;

    const stat = await filesystem.stat(plan.adapterCase.readPath);
    report.adapterStatSizeMatches = Number(stat.size) === plan.adapterCase.bytes;

    // `appendFile` is refused in every view that has one, because gate 5 does
    // not advertise `nativeAppend`. Proven here against the device rather than
    // against a fixture descriptor.
    try {
      await filesystem.appendFile(plan.adapterCase.writePath, 'x');
      report.adapterAppendRefused = 'ADMITTED';
    } catch (error) {
      report.adapterAppendRefused =
        error instanceof Stand ? error.label : (error as Error).name;
    }
  } finally {
    await filesystem.destroy();
    await remote.close();
  }
}

/* ------------------------------------------------------------------ *
 * Main
 * ------------------------------------------------------------------ */

/**
 * The TLS negative probe, run in its **own process** with the fixture CA
 * withheld.
 *
 * Verification cannot be turned off and on inside one process:
 * `NODE_EXTRA_CA_CERTS` is read once at startup. So the harness spawns this
 * driver a second time without it, and this mode makes the same descriptor
 * fetch against the same endpoint. The client must refuse with
 * `INSECURE_ENDPOINT` — its own code for "a certificate this side could not
 * verify", which it deliberately does not report as an outage and never marks
 * retryable, because retrying reaches the same untrusted peer.
 *
 * Without this, "the client verified the relay's certificate" is a sentence
 * about an environment variable that happened not to be set, not an
 * observation. The main run proves a verified chain is **accepted**; this
 * proves an unverifiable one is **refused**, and only the pair says
 * verification happened.
 */
async function tlsProbe(plan: Plan): Promise<void> {
  let code = 'ADMITTED';
  let retryable = true;
  try {
    await fetchDescriptor({ endpoint: plan.endpoints.readWrite, token: token(plan) });
  } catch (error) {
    code = codeOf(error);
    retryable = retryableOf(error);
  }
  emit({
    event: 'tls-probe',
    code,
    retryable,
    nodeTlsRejectUnauthorized: process.env['NODE_TLS_REJECT_UNAUTHORIZED'] ?? 'unset',
    extraCa: process.env['NODE_EXTRA_CA_CERTS'] ?? 'unset',
  });
}

async function main(): Promise<void> {
  const planPath = process.argv[2];
  if (planPath === undefined) {
    throw new Error('the plan file was not named');
  }
  const { readFile } = await import('node:fs/promises');
  const plan = JSON.parse(await readFile(planPath, 'utf8')) as Plan;
  if (process.argv[3] === '--tls-probe') {
    await tlsProbe(plan);
    return;
  }
  const report = blankReport();
  report.nodeTlsRejectUnauthorized = process.env['NODE_TLS_REJECT_UNAUTHORIZED'] ?? 'unset';
  // The path this driver actually resolved for the client under test, so the
  // harness compares a path node produced against the path it expects rather
  // than asking whether a file exists somewhere.
  //
  // `fileURLToPath` rather than stripping `file://` on the other side: a URL
  // percent-encodes a space and every non-ASCII byte, so a checkout under a
  // path containing either would have failed the comparison for a reason that
  // has nothing to do with which module was loaded. Decoding belongs where the
  // URL is, and node has the function for it.
  report.clientModulePath = fileURLToPath(import.meta.resolve('../src/index.ts'));
  const lines = createInterface({ input: process.stdin })[Symbol.asyncIterator]();

  // The order is load-bearing in one place and stated rather than left to be
  // inferred. Neither of the first two cases opens a filesystem session at all
  // — one is refused at the upgrade and one at discovery — so the `unknown`
  // case is the **first** exchange the device performs, which is what lets the
  // harness read its ledger as a delta from zero rather than having to
  // disentangle it from every other case's writes. `unknownCase` announces
  // itself and waits before returning, so nothing after it can start a second
  // exchange until the harness has taken that reading.
  const cases: [string, () => Promise<void>][] = [
    ['revision', () => revisionCase(plan, report, lines)],
    ['unauthenticated', () => unauthenticatedCase(plan, report)],
    ['unknown', () => unknownCase(plan, report, lines)],
    ['read-write', () => readWriteCase(plan, report)],
    ['read-only', () => readOnlyCase(plan, report, lines)],
    ['adapter', () => adapterCase(plan, report)],
  ];
  for (const [name, run] of cases) {
    try {
      await run();
    } catch (error) {
      // A closed label and the error's own code: never its message, which a
      // caller's own exception could have put a path into.
      report.failures.push(`${name}:${codeOf(error)}`);
      process.stderr.write(`gate6-e2e: case ${name} failed: ${codeOf(error)}\n`);
    }
  }
  await emitFinal({ event: 'report', report });
}

main().then(
  () => {
    process.exit(0);
  },
  (error: unknown) => {
    process.stderr.write(`gate6-e2e: the driver failed: ${(error as Error)?.name ?? 'unknown'}\n`);
    process.exit(1);
  },
);
