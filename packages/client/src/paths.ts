/**
 * The virtual path namespace, on the client's side of the wire.
 *
 * `docs/filesystem-api.md`: the confinement model "governs the device-side
 * provider; the adapters and the shared client inherit it and **may not widen
 * it**". So this refuses exactly what gate 1 refuses, by the same rules, in the
 * same fixed order — and it **rejects; it never rewrites**. Nothing here
 * normalises, folds, percent-decodes, Unicode-normalises or case-folds anything.
 *
 * Validating here is not a substitute for the provider's check and does not
 * pretend to be: the device refuses these paths whatever this client does, and
 * a malicious client can bypass this file by speaking 9P itself. What it buys
 * is that a caller's mistake is an error with a rule name attached rather than
 * an `EINVAL` from three layers away, and that the two implementations of one
 * table can be compared.
 *
 * The rule *names* are gate 1's own `PathRule::as_str` tokens, so a client
 * refusal and a device refusal of the same path are the same word.
 */

/** The stable diagnostic token for a refused path. Carries no path bytes. */
export type PathRule =
  | 'PATH_EMPTY'
  | 'PATH_NOT_ABSOLUTE'
  | 'PATH_TOO_LONG'
  | 'PATH_TOO_MANY_COMPONENTS'
  | 'PATH_COMPONENT_TOO_LONG'
  | 'PATH_EMPTY_COMPONENT'
  | 'PATH_DOT_COMPONENT'
  | 'PATH_DOTDOT_COMPONENT'
  | 'PATH_NUL'
  | 'PATH_CONTROL_CHARACTER'
  | 'PATH_BACKSLASH'
  | 'PATH_COLON'
  | 'PATH_RESERVED_DEVICE_NAME'
  | 'PATH_TRAILING_SPACE_OR_DOT'
  | 'PATH_COMPONENT_SEPARATOR';

/** A path this client refused before sending anything. */
export class PathRefusal extends Error {
  readonly rule: PathRule;

  constructor(rule: PathRule) {
    // The refused path is deliberately absent from the message: a caller knows
    // what it passed, and repeating it here would put it into every rendering.
    super(rule);
    this.name = 'PathRefusal';
    this.rule = rule;
  }
}

function refuse(rule: PathRule): never {
  throw new PathRefusal(rule);
}

/**
 * Reserved Windows device stems, refused on **every** host so an export's
 * namespace does not change meaning when the serving device changes operating
 * system. The superscript spellings are reserved by Microsoft beside the
 * ASCII-digit forms.
 */
export const RESERVED_DEVICE_STEMS: readonly string[] = [
  'CON',
  'PRN',
  'AUX',
  'NUL',
  'CONIN$',
  'CONOUT$',
  'COM0',
  'COM1',
  'COM2',
  'COM3',
  'COM4',
  'COM5',
  'COM6',
  'COM7',
  'COM8',
  'COM9',
  'COM¹',
  'COM²',
  'COM³',
  'LPT0',
  'LPT1',
  'LPT2',
  'LPT3',
  'LPT4',
  'LPT5',
  'LPT6',
  'LPT7',
  'LPT8',
  'LPT9',
  'LPT¹',
  'LPT²',
  'LPT³',
];

/** A fixed property of the namespace: every supported host's `NAME_MAX`. */
export const MAX_COMPONENT_BYTES = 255;

export interface PathBounds {
  /** The descriptor's `limits.maxPathBytes`. */
  maxPathBytes: number;
  /** The descriptor's `limits.maxPathComponents`. */
  maxPathComponents: number;
}

/**
 * The stem is the text before the first `.`, with **trailing ASCII spaces
 * removed**. The trim is load-bearing: `ntdll` strips them before comparing, so
 * `CON .txt` opens the console device without it.
 */
function asciiUpper(value: string): string {
  // ASCII-only, matching gate 1's `eq_ignore_ascii_case`. `String.toUpperCase`
  // is Unicode-aware and would fold code points the Rust leaves alone — `ß`
  // becomes `SS` and changes length — so two implementations of one table would
  // disagree on inputs neither intends to be equal.
  let out = '';
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    out += code >= 0x61 && code <= 0x7a ? String.fromCodePoint(code - 32) : character;
  }
  return out;
}

function isReservedDeviceStem(component: string): boolean {
  const stem = (component.split('.')[0] ?? component).replace(/ +$/u, '');
  const folded = asciiUpper(stem);
  return RESERVED_DEVICE_STEMS.some((reserved) => folded === reserved);
}

const encoder = new TextEncoder();

/** Whether this code unit is a C0 control or `DEL`. Nothing above is refused. */
function isRefusedControl(code: number): boolean {
  return code < 0x20 || code === 0x7f;
}

/**
 * Validate an absolute virtual path, returning its components.
 *
 * The checking order is gate 1's and is **not** the order of the table in the
 * contract: empty, total byte length, the leading separator, a whole-path scan
 * for NUL, backslash, colon and control characters, then per component. The
 * visible consequences are pinned by tests: `\a` reports `PATH_NOT_ABSOLUTE`
 * rather than `PATH_BACKSLASH`, and a 5,000-byte path containing `..` reports
 * `PATH_TOO_LONG`.
 */
export function validatePath(path: string, bounds: PathBounds): string[] {
  if (path.length === 0) {
    refuse('PATH_EMPTY');
  }
  if (encoder.encode(path).byteLength > bounds.maxPathBytes) {
    refuse('PATH_TOO_LONG');
  }
  if (!path.startsWith('/')) {
    refuse('PATH_NOT_ABSOLUTE');
  }
  for (const character of path) {
    const code = character.codePointAt(0) ?? 0;
    if (code === 0) {
      refuse('PATH_NUL');
    }
    if (character === '\\') {
      refuse('PATH_BACKSLASH');
    }
    if (character === ':') {
      refuse('PATH_COLON');
    }
    if (isRefusedControl(code)) {
      refuse('PATH_CONTROL_CHARACTER');
    }
  }
  const components = path.slice(1).split('/');
  // The root is the one path with no components, and it is legal.
  if (path === '/') {
    return [];
  }
  let seen = 0;
  for (const component of components) {
    seen += 1;
    if (seen > bounds.maxPathComponents) {
      refuse('PATH_TOO_MANY_COMPONENTS');
    }
    validateComponent(component);
  }
  return components;
}

/** The per-component rules, in gate 1's order. */
function validateComponent(component: string): void {
  if (component.length === 0) {
    refuse('PATH_EMPTY_COMPONENT');
  }
  if (encoder.encode(component).byteLength > MAX_COMPONENT_BYTES) {
    refuse('PATH_COMPONENT_TOO_LONG');
  }
  if (component === '.') {
    refuse('PATH_DOT_COMPONENT');
  }
  if (component === '..') {
    refuse('PATH_DOTDOT_COMPONENT');
  }
  if (component.endsWith('.') || component.endsWith(' ')) {
    refuse('PATH_TRAILING_SPACE_OR_DOT');
  }
  if (isReservedDeviceStem(component)) {
    refuse('PATH_RESERVED_DEVICE_NAME');
  }
}

/**
 * Validate one component handed to a path-building helper.
 *
 * A component that itself contains a `/` is refused under **its own** rule and
 * is not reported as an empty component: it is several components, and calling
 * it empty would misdescribe the input.
 */
export function validateComponentForJoin(component: string): string {
  if (component.includes('/')) {
    refuse('PATH_COMPONENT_SEPARATOR');
  }
  for (const character of component) {
    const code = character.codePointAt(0) ?? 0;
    if (code === 0) {
      refuse('PATH_NUL');
    }
    if (character === '\\') {
      refuse('PATH_BACKSLASH');
    }
    if (character === ':') {
      refuse('PATH_COLON');
    }
    if (isRefusedControl(code)) {
      refuse('PATH_CONTROL_CHARACTER');
    }
  }
  validateComponent(component);
  return component;
}

/** The parent of a validated path, and its final component. */
export function splitParent(path: string, bounds: PathBounds): { parent: string; name: string } {
  const components = validatePath(path, bounds);
  const name = components[components.length - 1];
  if (name === undefined) {
    // The root has no parent and no final component. Every caller of this
    // helper is naming a child, so this is a caller error rather than a path
    // the namespace refuses.
    refuse('PATH_EMPTY_COMPONENT');
  }
  const parent = `/${components.slice(0, -1).join('/')}`;
  return { parent, name };
}
