/**
 * Write the shared corpus, and this side's verdicts on it.
 *
 * ```sh
 * node fuzz/generate.ts                       # the committed seed and count
 * node fuzz/generate.ts --seed 0x1 --cases 64 # a different run, printed only
 * ```
 *
 * With no arguments it rewrites `fuzz/corpus.jsonl` and `fuzz/ts-verdicts.jsonl`
 * in place. With `--seed` or `--cases` it writes nothing and prints a summary,
 * so exploring another seed cannot silently replace the committed evidence.
 * The Rust side's verdicts on the committed corpus are produced separately by
 * `crates/tunnel-fs-ninep/tests/shared_fuzz.rs`.
 */

import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { CORPUS_CASES, CORPUS_SEED, generateCorpus, serializeCorpus } from './corpus.ts';
import { runCase, serializeVerdicts } from './canonical.ts';

const here = dirname(fileURLToPath(import.meta.url));

function argument(name: string): string | undefined {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? undefined : process.argv[index + 1];
}

const seedText = argument('seed');
const casesText = argument('cases');
const custom = seedText !== undefined || casesText !== undefined;
const seed = seedText === undefined ? CORPUS_SEED : BigInt(seedText);
const cases = casesText === undefined ? CORPUS_CASES : Number(casesText);

const corpus = generateCorpus(seed, cases);
const verdicts = corpus.map(runCase);

const accepted = verdicts.filter((verdict) => verdict.verdict === 'accept').length;
const refused = verdicts.filter((verdict) => verdict.verdict === 'refuse').length;
const streams = verdicts.filter((verdict) => verdict.verdict === 'stream').length;

if (custom) {
  process.stdout.write(
    `seed 0x${seed.toString(16)}, ${cases} cases: ${accepted} accepted, ${refused} refused, ${streams} streams (nothing written)\n`,
  );
} else {
  writeFileSync(join(here, 'corpus.jsonl'), serializeCorpus(seed, corpus));
  writeFileSync(join(here, 'ts-verdicts.jsonl'), serializeVerdicts(verdicts));
  process.stdout.write(
    `wrote ${cases} cases from seed 0x${seed.toString(16)}: ${accepted} accepted, ${refused} refused, ${streams} streams\n`,
  );
}
