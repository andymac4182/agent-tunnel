/**
 * The `.L` flag and mask rules.
 *
 * These are deliberately **not** in the codec. A frame carrying a flag the
 * profile denies is perfectly well framed: its size, type and tag are all
 * trustworthy, so the profile answers it with an `Rlerror` on its own tag and
 * keeps the session, rather than closing with 1002. `docs/filesystem-api.md`
 * names "a flag the profile denies" among the refusals a correct client can
 * recover from.
 *
 * The codec therefore decodes `flags[4]` and the mask words as opaque integers,
 * and a session layer — gate 6's, not written yet — calls these before
 * dispatching. Putting them inside `decodeBody` is what made the first version
 * of this file disagree with the Rust on the wire.
 */

import * as C from './constants.ts';
import { refuse } from './errors.ts';

export { ProfileRefusal } from './errors.ts';
export type { ProfileRefusalReason } from './errors.ts';

/**
 * `Tlopen` accepts the access mode, `O_TRUNC`, `O_APPEND`, `O_DIRECTORY` and
 * `O_NOFOLLOW` and nothing else. `O_CREAT` and `O_EXCL` are refused because
 * creation is `Tlcreate`; `O_NOFOLLOW` is accepted because gate 2's resolver
 * applies it unconditionally, so honouring a client that asks for it widens
 * nothing.
 */
export function checkTlopenFlags(flags: number): void {
  if ((flags & ~C.TLOPEN_FLAG_MASK) !== 0) {
    refuse('FlagNotInProfile', 'flags');
  }
  const access = flags & C.O_ACCMODE;
  if (access === 3) {
    refuse('FlagNotInProfile', 'flags.accmode');
  }
  const writable = access === C.O_WRONLY || access === C.O_RDWR;
  if (!writable && (flags & (C.O_TRUNC | C.O_APPEND)) !== 0) {
    refuse('FlagNotInProfile', 'flags.readonly-mutating');
  }
  if ((flags & C.O_DIRECTORY) !== 0 && (writable || (flags & C.O_TRUNC) !== 0)) {
    refuse('FlagNotInProfile', 'flags.directory-mutating');
  }
}

/**
 * `Tsetattr`'s mask excludes `uid`, `gid` and `ctime`, which is how "reject
 * unsupported ownership fields" is enforced. An empty mask is refused too: a
 * `Tsetattr` that changes nothing would be answered `Rsetattr`, reporting a
 * mutation that did not happen.
 */
export function checkTsetattrMask(valid: number): void {
  if (valid === 0) {
    refuse('EmptyMask', 'valid');
  }
  if ((valid & ~C.TSETATTR_VALID_MASK) !== 0) {
    refuse('MaskNotInProfile', 'valid');
  }
}

/** `Tgetattr`'s `request_mask` is bounded by `P9_GETATTR_ALL` and may not be zero. */
export function checkTgetattrMask(requestMask: bigint): void {
  if (requestMask === 0n) {
    refuse('EmptyMask', 'request_mask');
  }
  if ((requestMask & ~BigInt(C.GETATTR_ALL)) !== 0n) {
    refuse('MaskNotInProfile', 'request_mask');
  }
}

/** `Tunlinkat` accepts only `AT_REMOVEDIR`. */
export function checkTunlinkatFlags(flags: number): void {
  if ((flags & ~C.AT_REMOVEDIR) !== 0) {
    refuse('FlagNotInProfile', 'flags');
  }
}
