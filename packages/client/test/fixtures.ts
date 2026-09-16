import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));

/** The gate-3 fixture directory, read in place — the fixtures are not copied. */
export const FIXTURE_DIR = path.resolve(here, '../../../crates/tunnel-fs-ninep/fixtures');

export interface Fixture {
  /** The file's basename without `.hex`. */
  id: string;
  /** `# name:` from the header. */
  declaredName: string;
  /** The message-type spelling from `# type: Name (opcode)`. */
  declaredType: string;
  declaredOpcode: number;
  declaredTag: number;
  declaredSize: number;
  declaredMsize: number;
  bytes: Uint8Array;
}

/**
 * The three rules `fixtures/README.md` says a reader in any language needs:
 * strip `#` lines, strip whitespace, parse hex pairs.
 */
export function parseFixture(id: string, text: string): Fixture {
  const lines = text.split('\n');
  const header = lines.filter((line) => line.startsWith('#'));
  const hex = lines
    .filter((line) => !line.startsWith('#'))
    .join('')
    .replace(/\s+/g, '');

  if (hex.length % 2 !== 0) {
    throw new Error(`${id}: odd number of hex digits`);
  }
  if (!/^[0-9a-f]*$/.test(hex)) {
    throw new Error(`${id}: fixture hex is not lowercase hex`);
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }

  const field = (label: string): string => {
    const line = header.find((candidate) => candidate.startsWith(`# ${label}:`));
    if (line === undefined) {
      throw new Error(`${id}: fixture header has no "${label}" line`);
    }
    return line.slice(`# ${label}:`.length).trim();
  };

  const typeText = field('type');
  const typeMatch = /^([A-Za-z]+) \((\d+)\)$/.exec(typeText);
  if (typeMatch === null) {
    throw new Error(`${id}: cannot read "# type: Name (opcode)" from ${typeText}`);
  }
  const sizeText = field('size');
  const sizeMatch = /^(\d+) bytes, msize (\d+)$/.exec(sizeText);
  if (sizeMatch === null) {
    throw new Error(`${id}: cannot read "# size: N bytes, msize M" from ${sizeText}`);
  }

  return {
    id,
    declaredName: field('name'),
    declaredType: typeMatch[1]!,
    declaredOpcode: Number(typeMatch[2]),
    declaredTag: Number(field('tag')),
    declaredSize: Number(sizeMatch[1]),
    declaredMsize: Number(sizeMatch[2]),
    bytes,
  };
}

export function loadFixtures(): Fixture[] {
  const names = readdirSync(FIXTURE_DIR)
    .filter((name) => name.endsWith('.hex'))
    .sort();
  return names.map((name) =>
    parseFixture(name.slice(0, -'.hex'.length), readFileSync(path.join(FIXTURE_DIR, name), 'utf8')),
  );
}

export function loadIndex(): string[] {
  return readFileSync(path.join(FIXTURE_DIR, 'index.txt'), 'utf8')
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}
