import { fail } from './errors.ts';

/**
 * A bounded little-endian reader. Every read is checked against the slice's end
 * *before* it allocates or advances, so a declared length can never drive an
 * allocation larger than the bytes actually present.
 */
export class Reader {
  readonly bytes: Uint8Array;
  private readonly view: DataView;
  private offset = 0;

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  get remaining(): number {
    return this.bytes.byteLength - this.offset;
  }

  get position(): number {
    return this.offset;
  }

  private need(count: number, field: string): number {
    if (count > this.remaining) {
      fail('TruncatedBody', field);
    }
    const at = this.offset;
    this.offset += count;
    return at;
  }

  u8(field: string): number {
    return this.view.getUint8(this.need(1, field));
  }

  u16(field: string): number {
    return this.view.getUint16(this.need(2, field), true);
  }

  u32(field: string): number {
    return this.view.getUint32(this.need(4, field), true);
  }

  /** 64-bit fields are `BigInt` by contract; a `number` would lose bits above 2^53. */
  u64(field: string): bigint {
    return this.view.getBigUint64(this.need(8, field), true);
  }

  raw(count: number, field: string): Uint8Array {
    return this.bytes.subarray(this.need(count, field), this.offset);
  }

  /**
   * `string[s]`: a 16-bit BYTE count of UTF-8. Decoding is fatal — a byte
   * sequence that is not valid UTF-8 is refused by field and never replaced
   * with U+FFFD, because a substitution turns one host name into a different
   * one.
   */
  string(field: string): string {
    const length = this.u16(`${field}.length`);
    const raw = this.raw(length, field);
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(raw);
    } catch {
      return fail('InvalidUtf8', field);
    }
  }

  end(field: string): void {
    if (this.remaining !== 0) {
      fail('TrailingBytes', field);
    }
  }
}

/**
 * A growing little-endian writer.
 *
 * Every integer is range-checked before it is written. `DataView` truncates
 * silently — `setUint32(0, 2 ** 32)` stores zero and `setUint32(0, -1)` stores
 * `0xffffffff` — so without these checks `encode(message)` could produce bytes
 * that decode to something *other than* `message`, and a `Tclunk` with
 * `fid: -1` would quietly become `NOFID`. That would also hollow out the
 * "encoded from the expectation table alone" half of the fixture cross-check:
 * a table entry wrong above the field's width would still match the fixture.
 */
export class Writer {
  private chunks: Uint8Array[] = [];
  private length = 0;

  private push(bytes: Uint8Array): void {
    this.chunks.push(bytes);
    this.length += bytes.byteLength;
  }

  get byteLength(): number {
    return this.length;
  }

  private checkUnsigned(value: number, bits: number, field: string): void {
    if (!Number.isInteger(value) || value < 0 || value > 2 ** bits - 1) {
      fail('FieldOutOfRange', field);
    }
  }

  u8(value: number, field = 'u8'): void {
    this.checkUnsigned(value, 8, field);
    const out = new Uint8Array(1);
    new DataView(out.buffer).setUint8(0, value);
    this.push(out);
  }

  u16(value: number, field = 'u16'): void {
    this.checkUnsigned(value, 16, field);
    const out = new Uint8Array(2);
    new DataView(out.buffer).setUint16(0, value, true);
    this.push(out);
  }

  u32(value: number, field = 'u32'): void {
    this.checkUnsigned(value, 32, field);
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, value, true);
    this.push(out);
  }

  u64(value: bigint, field = 'u64'): void {
    if (typeof value !== 'bigint' || value < 0n || value > 0xffff_ffff_ffff_ffffn) {
      fail('FieldOutOfRange', field);
    }
    const out = new Uint8Array(8);
    new DataView(out.buffer).setBigUint64(0, value, true);
    this.push(out);
  }

  raw(bytes: Uint8Array): void {
    this.push(bytes);
  }

  string(value: string, field: string): void {
    const encoded = new TextEncoder().encode(value);
    if (encoded.byteLength > 0xffff) {
      fail('FieldTooLarge', field);
    }
    this.u16(encoded.byteLength);
    this.push(encoded);
  }

  finish(): Uint8Array {
    const out = new Uint8Array(this.length);
    let at = 0;
    for (const chunk of this.chunks) {
      out.set(chunk, at);
      at += chunk.byteLength;
    }
    return out;
  }
}
