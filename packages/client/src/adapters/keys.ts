/**
 * Object keys, for the one adapter whose framework does not speak in paths.
 *
 * Files SDK addresses objects by a relative key. `docs/filesystem-adapters.md`:
 * "Keys are nonempty relative paths for file operations. Reject leading `/`,
 * dot or parent segments, empty components, backslash/NUL and unsupported host
 * names. Percent signs are literal; do not decode keys into traversal. Only
 * listing accepts an empty prefix. Map `key` to virtual `/${key}`."
 *
 * So this is a **prefixing**, not a translation: the key becomes `/${key}` and
 * is then refused by gate 1's own rules, in gate 1's own order, by
 * `validatePath`. Nothing here normalises, folds or percent-decodes — the
 * namespace refuses; it never repairs — and the only rule this file adds is the
 * one Files SDK needs and the path namespace has no opinion about: a key is
 * relative, so a leading `/` is refused here rather than silently accepted as
 * the same object under two spellings.
 */

import { validatePath, type PathBounds, PathRefusal } from '../paths.ts';

/** The rule name for a key that is not a relative key. */
export type KeyRule = 'KEY_EMPTY' | 'KEY_ABSOLUTE' | 'KEY_TRAILING_SEPARATOR';

/** A key this adapter refused before sending anything. Carries no key bytes. */
export class KeyRefusal extends Error {
  readonly rule: KeyRule;

  constructor(rule: KeyRule) {
    super(rule);
    this.name = 'KeyRefusal';
    this.rule = rule;
  }
}

/**
 * The virtual path a nonempty file key names.
 *
 * Throws `KeyRefusal` for the two key-shaped refusals and `PathRefusal` for
 * everything the namespace itself refuses, so a caller can tell "this is not a
 * key" from "this names a path this profile cannot address".
 */
export function pathForKey(key: string, bounds: PathBounds): string {
  if (key.length === 0) {
    // "Ordinary operations require a nonempty file key. Only listing may use an
    // empty prefix."
    throw new KeyRefusal('KEY_EMPTY');
  }
  if (key.startsWith('/')) {
    throw new KeyRefusal('KEY_ABSOLUTE');
  }
  if (key.endsWith('/')) {
    // A trailing separator would become an empty final component, which the
    // namespace refuses as `PATH_EMPTY_COMPONENT` — a true rule, but the wrong
    // diagnosis: a key ending in `/` is a caller naming a directory in an
    // interface whose objects are files.
    throw new KeyRefusal('KEY_TRAILING_SEPARATOR');
  }
  const path = `/${key}`;
  validatePath(path, bounds);
  return path;
}

/**
 * The key a virtual path is seen as, in the object view.
 *
 * The inverse of `pathForKey` for any path it produced; used when a traversal
 * turns a discovered path back into a key for a listing.
 */
export function keyForPath(path: string): string {
  return path.startsWith('/') ? path.slice(1) : path;
}

/**
 * Check a listing prefix, which may be empty and need not name a whole
 * component.
 *
 * A prefix is matched against **keys**, not resolved as a path — "implement
 * prefix matching as object-key prefix matching, not just a directory lookup" —
 * so `pho` is a legal prefix that matches `photos/a.txt`. It is still refused
 * if it is absolute or contains a byte the namespace refuses anywhere in a
 * path, because a prefix that could never match a legal key is a caller error
 * rather than an empty page.
 */
export function checkPrefix(prefix: string, bounds: PathBounds): void {
  if (prefix.length === 0) {
    return;
  }
  if (prefix.startsWith('/')) {
    throw new KeyRefusal('KEY_ABSOLUTE');
  }
  // Validate the ancestor directory chain the prefix names in full, plus the
  // whole-path byte rules. The final segment may be a fragment of a name, so it
  // is checked only for the bytes no component may contain — `validatePath`
  // would otherwise refuse nothing extra for it, and would accept nothing more.
  const segments = prefix.split('/');
  const whole = segments.length > 1 ? `/${segments.slice(0, -1).join('/')}` : '/';
  validatePath(whole, bounds);
  const last = segments[segments.length - 1] ?? '';
  for (const character of last) {
    const code = character.codePointAt(0) ?? 0;
    if (code === 0 || character === '\\' || character === ':' || code < 0x20 || code === 0x7f) {
      throw new PathRefusal(
        code === 0
          ? 'PATH_NUL'
          : character === '\\'
            ? 'PATH_BACKSLASH'
            : character === ':'
              ? 'PATH_COLON'
              : 'PATH_CONTROL_CHARACTER',
      );
    }
  }
}
