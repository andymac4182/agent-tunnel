/**
 * A real endpoint on loopback, for the tests that need a socket.
 *
 * **What this is and what it is not.** It is a real `node:http` server on
 * 127.0.0.1: a real TCP connection, a real HTTP request, a real RFC 6455
 * handshake and real WebSocket frames, with the **WebSocket** half of the
 * framing written here rather than borrowed from the client under test — so
 * that layer is exercised against another implementation of it.
 *
 * Its **9P** layer is deliberately not independent: it encodes and decodes with
 * `src/ninep/`, the codec under test. Writing a third 9P implementation to
 * drive these tests would be a third thing to keep correct, and the second
 * opinion about 9P bytes already exists and is a better one — the shared corpus
 * in `fuzz/`, where the other implementation is `crates/tunnel-fs-ninep`.
 * Nothing this harness asserts should be read as independent evidence about the
 * wire format.
 *
 * It is **not** a relay and not a device. There is no TLS, no tunnel, no
 * logical stream, no grant, no provider and no filesystem: the 9P replies are
 * whatever the test says they are. Everything this harness proves is about the
 * client's side of the contract, and nothing it proves is about
 * interoperability with `crates/tunnel-relay` or `crates/tunnel-fs-provider`.
 * `docs/testing.md` is explicit that "constructing a compatible-looking object
 * or passing an in-process mock proves neither endpoint interoperability nor
 * authorization", and this harness makes no such claim.
 */

import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { Socket } from 'node:net';
import type { AddressInfo } from 'node:net';

import { decodeExact, encode } from '../../src/ninep/codec.ts';
import type { Message } from '../../src/ninep/messages.ts';
import { GRANT_REVISION_HEADER } from '../../src/descriptor.ts';

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

export interface ServerConnection {
  /** Send one 9P message as one binary frame. */
  send(message: Message): void;
  /** Send raw bytes as one binary frame, for the malformed-frame cases. */
  sendRaw(bytes: Uint8Array): void;
  /** Send one binary message split across continuation frames. */
  sendFragmented(message: Message, pieces: number): void;
  /** Send a text frame, which the profile refuses. */
  sendText(text: string): void;
  /** Close with a code, which is how the device ends a session. */
  close(code: number, reason?: string): void;
  /** Destroy the socket with no close frame at all. */
  destroy(): void;
  /** Every request this connection received, in order. */
  readonly received: Message[];
}

export interface EndpointOptions {
  /** Answered to an authenticated `GET` with no `Upgrade`. */
  descriptor?: unknown;
  /** Status and body for a `GET` that should fail. */
  descriptorFailure?: { status: number; body: unknown } | undefined;
  /** Status and body for an upgrade that should fail. */
  upgradeFailure?: { status: number; body: unknown } | undefined;
  /** Omit the subprotocol from the 101, which the client must refuse. */
  omitSubprotocol?: boolean;
  /** Answer with a wrong `Sec-WebSocket-Accept`. */
  wrongAccept?: boolean;
  /** Select an extension nothing offered. */
  selectExtension?: string | undefined;
  /** Drive the session. Called once per upgraded connection. */
  onConnection?: (connection: ServerConnection) => void;
  /** Called for each decoded request; return replies to send. */
  onRequest?: (message: Message, connection: ServerConnection) => void;
}

export interface Endpoint {
  url: string;
  /** Headers of the last descriptor `GET`, so a test can assert what was sent. */
  lastDescriptorHeaders: Record<string, string | string[] | undefined>;
  lastUpgradeHeaders: Record<string, string | string[] | undefined>;
  connections: ServerConnection[];
  close(): Promise<void>;
}

/** The server's half of RFC 6455 framing. Client frames are masked; ours are not. */
function serverFrame(opcode: number, payload: Uint8Array, fin = true): Uint8Array {
  const length = payload.byteLength;
  const headerLength = length < 126 ? 2 : length < 65536 ? 4 : 10;
  const frame = new Uint8Array(headerLength + length);
  frame[0] = (fin ? 0x80 : 0x00) | opcode;
  if (length < 126) {
    frame[1] = length;
  } else if (length < 65536) {
    frame[1] = 126;
    frame[2] = (length >> 8) & 0xff;
    frame[3] = length & 0xff;
  } else {
    frame[1] = 127;
    new DataView(frame.buffer).setBigUint64(2, BigInt(length));
  }
  frame.set(payload, headerLength);
  return frame;
}

class Connection implements ServerConnection {
  readonly received: Message[] = [];
  private buffer = new Uint8Array(0);
  private closed = false;

  private readonly socket: Socket;
  private readonly options: EndpointOptions;
  private readonly msize: number;

  constructor(socket: Socket, options: EndpointOptions, msize: number) {
    this.socket = socket;
    this.options = options;
    this.msize = msize;
    socket.on('data', (chunk: Buffer) => {
      this.consume(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength));
    });
    socket.on('error', () => {
      this.closed = true;
    });
  }

  private consume(chunk: Uint8Array): void {
    const merged = new Uint8Array(this.buffer.byteLength + chunk.byteLength);
    merged.set(this.buffer, 0);
    merged.set(chunk, this.buffer.byteLength);
    this.buffer = merged;
    for (;;) {
      if (this.buffer.byteLength < 2) {
        return;
      }
      const first = this.buffer[0] ?? 0;
      const second = this.buffer[1] ?? 0;
      const opcode = first & 0x0f;
      const masked = (second & 0x80) !== 0;
      let length = second & 0x7f;
      let offset = 2;
      if (length === 126) {
        if (this.buffer.byteLength < 4) {
          return;
        }
        length = ((this.buffer[2] ?? 0) << 8) | (this.buffer[3] ?? 0);
        offset = 4;
      } else if (length === 127) {
        if (this.buffer.byteLength < 10) {
          return;
        }
        length = Number(
          new DataView(
            this.buffer.buffer,
            this.buffer.byteOffset,
            this.buffer.byteLength,
          ).getBigUint64(2),
        );
        offset = 10;
      }
      const keyAt = offset;
      if (masked) {
        offset += 4;
      }
      if (this.buffer.byteLength < offset + length) {
        return;
      }
      const raw = this.buffer.slice(offset, offset + length);
      if (masked) {
        for (let index = 0; index < raw.byteLength; index += 1) {
          raw[index] = (raw[index] ?? 0) ^ (this.buffer[keyAt + (index % 4)] ?? 0);
        }
      }
      this.buffer = this.buffer.subarray(offset + length);
      if (opcode === 0x8) {
        this.closed = true;
        this.socket.end();
        return;
      }
      if (opcode === 0x2) {
        const message = decodeExact(raw, { msize: this.msize });
        this.received.push(message);
        this.options.onRequest?.(message, this);
      }
    }
  }

  send(message: Message): void {
    this.sendRaw(encode(message, { msize: this.msize }));
  }

  sendRaw(bytes: Uint8Array): void {
    if (!this.closed) {
      this.socket.write(serverFrame(0x2, bytes));
    }
  }

  sendFragmented(message: Message, pieces: number): void {
    const bytes = encode(message, { msize: this.msize });
    const size = Math.ceil(bytes.byteLength / pieces);
    for (let index = 0; index * size < bytes.byteLength; index += 1) {
      const slice = bytes.subarray(index * size, (index + 1) * size);
      const last = (index + 1) * size >= bytes.byteLength;
      this.socket.write(serverFrame(index === 0 ? 0x2 : 0x0, slice, last));
    }
  }

  sendText(text: string): void {
    this.socket.write(serverFrame(0x1, new TextEncoder().encode(text)));
  }

  close(code: number, reason = ''): void {
    const reasonBytes = new TextEncoder().encode(reason);
    const payload = new Uint8Array(2 + reasonBytes.byteLength);
    payload[0] = (code >> 8) & 0xff;
    payload[1] = code & 0xff;
    payload.set(reasonBytes, 2);
    this.socket.write(serverFrame(0x8, payload));
    this.closed = true;
    setTimeout(() => this.socket.end(), 5).unref?.();
  }

  destroy(): void {
    this.closed = true;
    this.socket.destroy();
  }
}

/** Start the endpoint. `msize` bounds what the harness itself encodes. */
export async function startEndpoint(options: EndpointOptions, msize = 65536): Promise<Endpoint> {
  const connections: Connection[] = [];
  const endpoint: Partial<Endpoint> = { connections };

  const server: Server = createServer((request: IncomingMessage, response: ServerResponse) => {
    endpoint.lastDescriptorHeaders = request.headers;
    const failure = options.descriptorFailure;
    if (failure !== undefined) {
      response.writeHead(failure.status, {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
      });
      response.end(JSON.stringify(failure.body));
      return;
    }
    response.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    response.end(JSON.stringify(options.descriptor));
  });

  server.on('upgrade', (request: IncomingMessage, socket: Socket) => {
    endpoint.lastUpgradeHeaders = request.headers;
    const rejection = options.upgradeFailure;
    if (rejection !== undefined) {
      const body = JSON.stringify(rejection.body);
      socket.write(
        `HTTP/1.1 ${rejection.status} Refused\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`,
      );
      socket.end();
      return;
    }
    const key = request.headers['sec-websocket-key'] ?? '';
    const accept = options.wrongAccept === true
      ? 'not-the-right-hash'
      : createHash('sha1')
          .update(String(key) + GUID)
          .digest('base64');
    const lines = [
      'HTTP/1.1 101 Switching Protocols',
      'Upgrade: websocket',
      'Connection: Upgrade',
      `Sec-WebSocket-Accept: ${accept}`,
    ];
    if (options.omitSubprotocol !== true) {
      lines.push('Sec-WebSocket-Protocol: agent-tunnel.9p.v1');
    }
    if (options.selectExtension !== undefined) {
      lines.push(`Sec-WebSocket-Extensions: ${options.selectExtension}`);
    }
    socket.write(`${lines.join('\r\n')}\r\n\r\n`);
    const connection = new Connection(socket, options, msize);
    connections.push(connection);
    options.onConnection?.(connection);
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address() as AddressInfo;
  endpoint.url = `http://127.0.0.1:${address.port}/v1/devices/device-123/services/workspace/fs`;
  endpoint.close = () =>
    new Promise<void>((resolve) => {
      for (const connection of connections) {
        connection.destroy();
      }
      server.close(() => resolve());
    });
  return endpoint as Endpoint;
}

/** The grant revision a request carried, for the header assertions. */
export function grantRevisionOf(headers: Record<string, string | string[] | undefined>): string {
  const value = headers[GRANT_REVISION_HEADER.toLowerCase()];
  return Array.isArray(value) ? (value[0] ?? '') : (value ?? '');
}
