/**
 * A WebSocket client, written out, because the profile needs one that can set
 * `Authorization` on the upgrade.
 *
 * `docs/filesystem-api.md`: "Use an access-token supplier and a WebSocket
 * implementation that can send Authorization on upgrade; native browser
 * WebSocket cannot set that header." Node 24's global `WebSocket` is the
 * browser API and has the same limitation, and this package has **zero runtime
 * dependencies**, so `ws` is not available either. What is left is RFC 6455's
 * client half over `node:http`'s own upgrade, which is what this is: the
 * handshake, the frame codec, masking, fragment reassembly, ping/pong and the
 * close handshake, bounded by the profile's message ceiling.
 *
 * It implements only what this profile uses. Per-message compression is not
 * offered and a server offering it is refused rather than tolerated — which is
 * stronger than gate 4's "off because nothing enables it", and is this side's
 * half of the contract's "disable per-message compression initially".
 */

import { createHash, randomBytes } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import type { Socket } from 'node:net';
import type { ClientRequest, IncomingMessage } from 'node:http';

import { FilesystemError } from './errors.ts';

/**
 * Node's error codes for "this peer's certificate could not be verified".
 *
 * A TLS failure must not look like an outage: reporting it `BACKEND_UNAVAILABLE`
 * with `retryable: true` tells a caller to try again, when what actually
 * happened is that the endpoint could not be trusted and trying again will
 * reach the same untrusted peer. It is reported as `INSECURE_ENDPOINT`, which is
 * the same answer a plain-HTTP endpoint gets and is never retryable.
 */
export function isTlsVerificationFailure(error: unknown): boolean {
  const code = (error as { code?: unknown }).code;
  if (typeof code !== 'string') {
    return false;
  }
  return (
    code.startsWith('ERR_TLS') ||
    code.startsWith('ERR_SSL') ||
    code.includes('CERT') ||
    code.includes('CERTIFICATE') ||
    code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' ||
    code === 'SELF_SIGNED_CERT_IN_CHAIN' ||
    code === 'EPROTO'
  );
}

/** RFC 6455's fixed GUID for the accept hash. */
const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

const OPCODE_CONTINUATION = 0x0;
const OPCODE_TEXT = 0x1;
const OPCODE_BINARY = 0x2;
const OPCODE_CLOSE = 0x8;
const OPCODE_PING = 0x9;
const OPCODE_PONG = 0xa;

export interface CloseInfo {
  /** The peer's close code, or `1006` when the socket ended without one. */
  code: number;
  /** The close reason, which the contract bounds to sanitized identifiers. */
  reason: string;
  /** True when this side initiated the close. */
  local: boolean;
}

export interface TransportHandlers {
  /** One complete binary message. Fragments are already reassembled. */
  onMessage: (bytes: Uint8Array) => void;
  onClose: (info: CloseInfo) => void;
}

/**
 * What the 9P session needs from a transport.
 *
 * Named as an interface so the session can be driven over a real socket and
 * over anything else that speaks the same frames — and so the one thing that
 * cannot be true of a fake, that the bytes crossed a socket, stays visible in
 * the type rather than being assumed.
 */
export interface BinaryTransport {
  send(bytes: Uint8Array): void;
  close(code: number, reason?: string): void;
  readonly isOpen: boolean;
}

export interface UpgradeOptions {
  /** The `https:`/`wss:` endpoint. The scheme is checked, not rewritten. */
  url: URL;
  subprotocol: string;
  headers: Record<string, string>;
  /** The largest complete message this side will reassemble. */
  maxMessageBytes: number;
  /**
   * Permit `http:` to a loopback host. TLS verification is mandatory outside
   * "the explicit loopback development harness", and this is that harness: it
   * is off by default and a non-loopback host is refused even when it is on.
   */
  allowInsecureLoopback?: boolean;
  /**
   * A bounded deadline for the handshake, in milliseconds.
   *
   * A peer can accept a TCP connection and then say nothing, so without this
   * there is no deadline anywhere in `connectFilesystem`'s path: `fetch` has
   * the caller's signal, and the upgrade had neither.
   */
  timeoutMs?: number | undefined;
  /** The caller's own cancellation, honoured during the handshake. */
  signal?: AbortSignal | undefined;
  handlers: TransportHandlers;
}

function fail(
  code: 'INVALID_UPGRADE' | 'INSECURE_ENDPOINT' | 'SUBPROTOCOL_REQUIRED' | 'DEADLINE_EXCEEDED' | 'ABORTED',
  detail: string,
): never {
  throw new FilesystemError({
    code,
    operation: `upgrade:${detail}`,
    outcome: 'not_started',
    retryable: false,
  });
}

/**
 * Whether this URL's host is a loopback **address**.
 *
 * Decided by address only — `127.0.0.0/8` and `::1` — and never by name.
 * `localhost` used to be in this set, and it is a name a `hosts` file or a DNS
 * answer can point anywhere: with the insecure opt-in set, that would have sent
 * a bearer token in clear to whatever the name resolved to. A name is not an
 * address, and the development harness this exists for always has one.
 */
export function isLoopback(url: URL): boolean {
  const host = url.hostname.replace(/^\[|\]$/gu, '');
  if (host === '::1' || host === '0:0:0:0:0:0:0:1') {
    return true;
  }
  const octets = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/u.exec(host);
  if (octets === null) {
    return false;
  }
  const parts = octets.slice(1).map((part) => Number(part));
  if (parts.some((part) => part > 255)) {
    return false;
  }
  return parts[0] === 127;
}

/**
 * Check the endpoint before anything is sent to it.
 *
 * "TLS certificate verification is mandatory outside the explicit loopback
 * development harness." A plain-HTTP endpoint therefore fails here rather than
 * being silently upgraded or silently accepted, and the escape hatch is both
 * explicit and confined to a loopback host.
 */
export function requireSecureEndpoint(url: URL, allowInsecureLoopback: boolean): void {
  if (url.protocol === 'https:' || url.protocol === 'wss:') {
    return;
  }
  if ((url.protocol === 'http:' || url.protocol === 'ws:') && allowInsecureLoopback && isLoopback(url)) {
    return;
  }
  fail('INSECURE_ENDPOINT', 'scheme');
}

/**
 * Mask a client frame in place, as RFC 6455 requires of every client frame.
 *
 * The key is from `randomBytes`: the masking is not a security property, but a
 * predictable key is a documented proxy-poisoning hazard, and a counter would
 * be predictable.
 */
function maskInto(payload: Uint8Array, key: Uint8Array): Uint8Array {
  const out = new Uint8Array(payload.byteLength);
  for (let index = 0; index < payload.byteLength; index += 1) {
    out[index] = (payload[index] ?? 0) ^ (key[index % 4] ?? 0);
  }
  return out;
}

function buildFrame(opcode: number, payload: Uint8Array): Uint8Array {
  const key = randomBytes(4);
  const masked = maskInto(payload, key);
  const length = payload.byteLength;
  const headerLength = length < 126 ? 2 : length < 65536 ? 4 : 10;
  const frame = new Uint8Array(headerLength + 4 + length);
  frame[0] = 0x80 | opcode; // FIN, one frame per message: this profile never splits.
  if (length < 126) {
    frame[1] = 0x80 | length;
  } else if (length < 65536) {
    frame[1] = 0x80 | 126;
    frame[2] = (length >> 8) & 0xff;
    frame[3] = length & 0xff;
  } else {
    frame[1] = 0x80 | 127;
    const view = new DataView(frame.buffer);
    view.setBigUint64(2, BigInt(length));
  }
  frame.set(key, headerLength);
  frame.set(masked, headerLength + 4);
  return frame;
}

/** A frame decoder for the server→client direction, where nothing is masked. */
class FrameReader {
  private buffer = new Uint8Array(0);
  private fragments: Uint8Array[] = [];
  private fragmentOpcode: number | undefined;
  private fragmentBytes = 0;
  private readonly maxMessageBytes: number;

  constructor(maxMessageBytes: number) {
    this.maxMessageBytes = maxMessageBytes;
  }

  /** Push bytes; get complete messages and control frames back. */
  push(chunk: Uint8Array): { messages: Uint8Array[]; control: { opcode: number; payload: Uint8Array }[]; error?: string } {
    const merged = new Uint8Array(this.buffer.byteLength + chunk.byteLength);
    merged.set(this.buffer, 0);
    merged.set(chunk, this.buffer.byteLength);
    this.buffer = merged;

    const messages: Uint8Array[] = [];
    const control: { opcode: number; payload: Uint8Array }[] = [];
    for (;;) {
      if (this.buffer.byteLength < 2) {
        return { messages, control };
      }
      const first = this.buffer[0] ?? 0;
      const second = this.buffer[1] ?? 0;
      const fin = (first & 0x80) !== 0;
      if ((first & 0x70) !== 0) {
        // A reserved bit set means an extension this side never negotiated —
        // `permessage-deflate` above all. Refusing is the point.
        return { messages, control, error: 'reserved-bits' };
      }
      const opcode = first & 0x0f;
      const masked = (second & 0x80) !== 0;
      if (masked) {
        // "A server MUST NOT mask any frames that it sends to the client."
        return { messages, control, error: 'masked-server-frame' };
      }
      let length = second & 0x7f;
      let offset = 2;
      if (length === 126) {
        if (this.buffer.byteLength < 4) {
          return { messages, control };
        }
        length = ((this.buffer[2] ?? 0) << 8) | (this.buffer[3] ?? 0);
        offset = 4;
      } else if (length === 127) {
        if (this.buffer.byteLength < 10) {
          return { messages, control };
        }
        const big = new DataView(
          this.buffer.buffer,
          this.buffer.byteOffset,
          this.buffer.byteLength,
        ).getBigUint64(2);
        if (big > BigInt(this.maxMessageBytes)) {
          return { messages, control, error: 'frame-above-limit' };
        }
        length = Number(big);
        offset = 10;
      }
      const isControl = (opcode & 0x08) !== 0;
      if (isControl && (length > 125 || !fin)) {
        // Control frames are never fragmented and never longer than 125 bytes.
        return { messages, control, error: 'bad-control-frame' };
      }
      if (length > this.maxMessageBytes) {
        return { messages, control, error: 'frame-above-limit' };
      }
      if (this.buffer.byteLength < offset + length) {
        return { messages, control };
      }
      const payload = this.buffer.slice(offset, offset + length);
      this.buffer = this.buffer.subarray(offset + length);

      if (isControl) {
        control.push({ opcode, payload });
        continue;
      }
      if (opcode === OPCODE_TEXT) {
        // "Reject text": one complete 9P message per **binary** message, and a
        // text frame is a peer that misread the profile.
        return { messages, control, error: 'text-frame' };
      }
      if (opcode === OPCODE_BINARY) {
        if (this.fragmentOpcode !== undefined) {
          return { messages, control, error: 'interleaved-fragments' };
        }
        if (fin) {
          messages.push(payload);
          continue;
        }
        this.fragmentOpcode = opcode;
        this.fragments = [payload];
        this.fragmentBytes = payload.byteLength;
        continue;
      }
      if (opcode === OPCODE_CONTINUATION) {
        if (this.fragmentOpcode === undefined) {
          return { messages, control, error: 'continuation-without-start' };
        }
        this.fragmentBytes += payload.byteLength;
        if (this.fragmentBytes > this.maxMessageBytes) {
          // "WS fragmentation is reassembled under the same size limit."
          return { messages, control, error: 'message-above-limit' };
        }
        this.fragments.push(payload);
        if (fin) {
          const whole = new Uint8Array(this.fragmentBytes);
          let at = 0;
          for (const part of this.fragments) {
            whole.set(part, at);
            at += part.byteLength;
          }
          this.fragments = [];
          this.fragmentOpcode = undefined;
          this.fragmentBytes = 0;
          messages.push(whole);
        }
        continue;
      }
      return { messages, control, error: 'unknown-opcode' };
    }
  }
}

class SocketTransport implements BinaryTransport {
  private open = true;
  private closeSent = false;

  private readonly socket: Socket;
  private readonly handlers: TransportHandlers;
  private readonly reader: FrameReader;

  constructor(socket: Socket, handlers: TransportHandlers, reader: FrameReader) {
    this.socket = socket;
    this.handlers = handlers;
    this.reader = reader;
    socket.on('data', (chunk: Buffer) => {
      this.consume(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength));
    });
    socket.on('close', () => {
      // 1006 is "no close frame was received", which is exactly what happened.
      this.finish({ code: 1006, reason: '', local: false });
    });
    socket.on('error', () => {
      this.finish({ code: 1006, reason: '', local: false });
    });
  }

  get isOpen(): boolean {
    return this.open;
  }

  private consume(chunk: Uint8Array): void {
    const { messages, control, error } = this.reader.push(chunk);
    for (const message of messages) {
      if (!this.open) {
        return;
      }
      this.handlers.onMessage(message);
    }
    for (const frame of control) {
      if (frame.opcode === OPCODE_PING) {
        this.write(buildFrame(OPCODE_PONG, frame.payload));
      } else if (frame.opcode === OPCODE_CLOSE) {
        const code =
          frame.payload.byteLength >= 2
            ? ((frame.payload[0] ?? 0) << 8) | (frame.payload[1] ?? 0)
            : 1005;
        const reason = new TextDecoder('utf-8', { fatal: false }).decode(frame.payload.subarray(2));
        if (!this.closeSent) {
          // A close payload is either empty or at least a two-byte code. One
          // stray byte is neither, and echoing it back would answer a malformed
          // frame with another one, so the reply carries no payload at all.
          const echo =
            frame.payload.byteLength >= 2 ? frame.payload.subarray(0, 2) : new Uint8Array(0);
          this.write(buildFrame(OPCODE_CLOSE, echo));
          this.closeSent = true;
        }
        this.socket.end();
        this.finish({ code, reason, local: false });
        return;
      }
      // A pong is not tracked: nothing here sends a ping, so an unsolicited
      // pong is permitted by RFC 6455 and means nothing to this profile.
    }
    if (error !== undefined) {
      this.close(1002, error);
    }
  }

  private write(bytes: Uint8Array): void {
    if (this.socket.writable) {
      this.socket.write(bytes);
    }
  }

  send(bytes: Uint8Array): void {
    if (!this.open) {
      throw new FilesystemError({
        code: 'SESSION_LOST',
        operation: 'transport:send',
        outcome: 'not_started',
        retryable: false,
      });
    }
    this.write(buildFrame(OPCODE_BINARY, bytes));
  }

  close(code: number, reason = ''): void {
    if (!this.open) {
      return;
    }
    if (!this.closeSent) {
      const reasonBytes = new TextEncoder().encode(reason);
      const payload = new Uint8Array(2 + Math.min(reasonBytes.byteLength, 123));
      payload[0] = (code >> 8) & 0xff;
      payload[1] = code & 0xff;
      payload.set(reasonBytes.subarray(0, payload.byteLength - 2), 2);
      this.write(buildFrame(OPCODE_CLOSE, payload));
      this.closeSent = true;
    }
    this.socket.end();
    this.finish({ code, reason, local: true });
  }

  private finish(info: CloseInfo): void {
    if (!this.open) {
      return;
    }
    this.open = false;
    this.socket.destroy();
    this.handlers.onClose(info);
  }
}

/**
 * Perform the upgrade and return a transport.
 *
 * The handshake is verified rather than assumed: the status must be 101, the
 * `Sec-WebSocket-Accept` must be the hash of the key this side generated, and
 * the server must have **selected** the subprotocol. A server that answered 101
 * without selecting it is refused — the subprotocol is what chose the 9P
 * dialect, so continuing without it would be speaking 9P at something that
 * never agreed to hear it.
 */
export function upgrade(options: UpgradeOptions): Promise<BinaryTransport> {
  requireSecureEndpoint(options.url, options.allowInsecureLoopback ?? false);
  const key = randomBytes(16).toString('base64');
  const expected = createHash('sha1')
    .update(key + GUID)
    .digest('base64');
  const secure = options.url.protocol === 'https:' || options.url.protocol === 'wss:';
  const send = secure ? httpsRequest : httpRequest;

  return new Promise<BinaryTransport>((resolve, reject) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let onAbort: (() => void) | undefined;
    const finish = (): void => {
      settled = true;
      if (timer !== undefined) {
        clearTimeout(timer);
      }
      if (onAbort !== undefined) {
        options.signal?.removeEventListener('abort', onAbort);
      }
    };
    const httpUrl = new URL(options.url.toString());
    httpUrl.protocol = secure ? 'https:' : 'http:';
    const outgoing: ClientRequest = send(httpUrl, {
      headers: {
        ...options.headers,
        Connection: 'Upgrade',
        Upgrade: 'websocket',
        'Sec-WebSocket-Key': key,
        'Sec-WebSocket-Version': '13',
        'Sec-WebSocket-Protocol': options.subprotocol,
      },
      // A redirect is never followed on this path: the contract says not to
      // follow cross-origin redirects or trust an arbitrary WS URL, and
      // `node:http` does not follow them on its own.
    });

    outgoing.on('upgrade', (response: IncomingMessage, socket: Socket, head: Buffer) => {
      if (settled) {
        socket.destroy();
        return;
      }
      finish();
      const accept = response.headers['sec-websocket-accept'];
      const selected = response.headers['sec-websocket-protocol'];
      const extensions = response.headers['sec-websocket-extensions'];
      if (accept !== expected) {
        socket.destroy();
        reject(new FilesystemError({ code: 'INVALID_UPGRADE', operation: 'upgrade:accept', outcome: 'not_started', retryable: false }));
        return;
      }
      if (selected !== options.subprotocol) {
        socket.destroy();
        reject(new FilesystemError({ code: 'SUBPROTOCOL_REQUIRED', operation: 'upgrade:subprotocol', outcome: 'not_started', retryable: false }));
        return;
      }
      if (extensions !== undefined && extensions !== '') {
        // Nothing was offered, so nothing may be selected. This is stronger
        // than "compression is off because nothing enables it".
        socket.destroy();
        reject(new FilesystemError({ code: 'INVALID_UPGRADE', operation: 'upgrade:extensions', outcome: 'not_started', retryable: false }));
        return;
      }
      socket.setNoDelay(true);
      const transport = new SocketTransport(
        socket,
        options.handlers,
        new FrameReader(options.maxMessageBytes),
      );
      resolve(transport);
      if (head.byteLength > 0) {
        socket.unshift(head);
      }
    });

    outgoing.on('response', (response: IncomingMessage) => {
      if (settled) {
        response.destroy();
        return;
      }
      finish();
      // Not an upgrade: the endpoint answered the contract's JSON error body,
      // and the caller needs its code rather than "the socket failed".
      const chunks: Buffer[] = [];
      response.on('data', (chunk: Buffer) => chunks.push(chunk));
      response.on('end', () => {
        reject(
          new UpgradeRejected(response.statusCode ?? 0, Buffer.concat(chunks).toString('utf8')),
        );
      });
    });

    outgoing.on('error', (error: unknown) => {
      if (settled) {
        return;
      }
      finish();
      const tls = isTlsVerificationFailure(error);
      reject(
        new FilesystemError({
          code: tls ? 'INSECURE_ENDPOINT' : 'BACKEND_UNAVAILABLE',
          operation: tls ? 'upgrade:tls' : 'upgrade:connect',
          outcome: 'not_started',
          // A certificate this side could not verify is not an outage, and
          // telling a caller to retry it would be telling it to reach the same
          // untrusted peer again.
          retryable: !tls,
        }),
      );
    });

    if (options.signal !== undefined) {
      if (options.signal.aborted) {
        finish();
        outgoing.destroy();
        reject(
          new FilesystemError({
            code: 'ABORTED',
            operation: 'upgrade:signal',
            outcome: 'not_started',
            retryable: false,
          }),
        );
        return;
      }
      onAbort = (): void => {
        if (settled) {
          return;
        }
        finish();
        outgoing.destroy();
        reject(
          new FilesystemError({
            code: 'ABORTED',
            operation: 'upgrade:signal',
            outcome: 'not_started',
            retryable: false,
          }),
        );
      };
      options.signal.addEventListener('abort', onAbort, { once: true });
    }
    if (options.timeoutMs !== undefined && options.timeoutMs > 0) {
      timer = setTimeout(() => {
        if (settled) {
          return;
        }
        finish();
        outgoing.destroy();
        reject(
          new FilesystemError({
            code: 'DEADLINE_EXCEEDED',
            operation: 'upgrade:deadline',
            outcome: 'not_started',
            retryable: true,
          }),
        );
      }, options.timeoutMs);
      timer.unref?.();
    }
    outgoing.end();
  });
}

/** The endpoint answered the upgrade with an ordinary HTTP response. */
export class UpgradeRejected extends Error {
  readonly status: number;
  readonly body: string;

  constructor(status: number, body: string) {
    super(`upgrade refused with ${status}`);
    this.name = 'UpgradeRejected';
    this.status = status;
    this.body = body;
  }
}
