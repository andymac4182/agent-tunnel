/**
 * The shared fuzzing `docs/testing.md` requires: one generated corpus, run
 * against **both** 9P2000.L codecs, with the accepted values compared.
 *
 * Gate 3's residue is explicit that its fixture cross-check is not this — "no
 * input is generated, and the two codecs are never run against one another's
 * output on anything outside the 43". Here a corpus is generated in one place,
 * deterministically from a seed the corpus file records, and both
 * implementations produce a verdict on every case. The rule is that they must
 * **accept and agree**, or **both refuse**; anything else fails this test.
 *
 * The Rust verdicts are produced by
 * `crates/tunnel-fs-ninep/tests/shared_fuzz.rs` and checked in beside the
 * corpus, because `npm test` must run offline with `node_modules` deleted and
 * cannot invoke cargo. That test re-derives them from the same corpus and fails
 * if the checked-in file is stale, so the evidence cannot drift from the code
 * it describes:
 *
 * ```sh
 * cargo test -p tunnel-fs-ninep --test shared_fuzz
 * ```
 *
 * A failing case is reproducible from the seed alone:
 *
 * ```sh
 * node fuzz/generate.ts --seed 0x5ca1ab1e9f2000 --cases 4096
 * ```
 */

import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  CORPUS_CASES,
  CORPUS_SEED,
  generateCorpus,
  serializeCorpus,
  type Case,
} from '../fuzz/corpus.ts';
import { runCase, serializeVerdicts, type Verdict } from '../fuzz/canonical.ts';

const fuzzDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'fuzz');

function readLines(name: string): string[] {
  return readFileSync(join(fuzzDir, name), 'utf8').trimEnd().split('\n');
}

const corpus: Case[] = generateCorpus(CORPUS_SEED, CORPUS_CASES);
const ours: Verdict[] = corpus.map(runCase);
const theirs: Verdict[] = readLines('rust-verdicts.jsonl').map(
  (line) => JSON.parse(line) as Verdict,
);

describe('the shared corpus', () => {
  it('is exactly what the committed seed generates', () => {
    // The corpus is committed so the Rust side can read it without running
    // this generator, and regenerated here so a hand-edited corpus — one
    // trimmed to the cases that happen to agree, say — fails rather than
    // quietly narrowing the cross-check.
    assert.equal(serializeCorpus(CORPUS_SEED, corpus), readFileSync(join(fuzzDir, 'corpus.jsonl'), 'utf8'));
  });

  it('this side’s committed verdicts are what this side now produces', () => {
    assert.equal(serializeVerdicts(ours), readFileSync(join(fuzzDir, 'ts-verdicts.jsonl'), 'utf8'));
  });

  it('reaches enough of the protocol to be worth comparing', () => {
    const kinds = new Set<string>();
    const reasons = new Set<string>();
    let accepted = 0;
    for (const verdict of ours) {
      if (verdict.verdict === 'accept') {
        accepted += 1;
        kinds.add(verdict.value.split(' ')[0] ?? '');
      } else if (verdict.verdict === 'refuse') {
        reasons.add(verdict.reason);
      } else {
        for (const value of verdict.values) {
          kinds.add(value.split(' ')[0] ?? '');
        }
        if (verdict.reason !== null) {
          reasons.add(verdict.reason);
        }
      }
    }
    // A corpus that only ever produced garbage would agree for free.
    assert.ok(accepted > 500, `only ${accepted} cases were accepted`);
    assert.ok(kinds.size >= 38, `only ${kinds.size} message types were decoded: ${[...kinds]}`);
    assert.ok(reasons.size >= 12, `only ${reasons.size} refusal reasons were reached`);
  });
});

describe('both codecs on every case', () => {
  it('accept and agree, or both refuse', () => {
    assert.equal(theirs.length, ours.length, 'the two verdict files cover different corpora');
    const disagreements: string[] = [];
    for (const [index, mine] of ours.entries()) {
      const other = theirs[index];
      assert.ok(other !== undefined);
      assert.equal(other.id, mine.id, `verdict ${index} is for a different case`);
      const render = (verdict: Verdict): string => JSON.stringify(verdict);
      if (render(mine) !== render(other)) {
        disagreements.push(
          `case ${mine.id} (${JSON.stringify(corpus[mine.id])}):\n  ts   ${render(mine)}\n  rust ${render(other)}`,
        );
      }
    }
    assert.deepEqual(
      disagreements,
      [],
      `${disagreements.length} disagreements:\n${disagreements.slice(0, 5).join('\n')}`,
    );
  });

  it('agree on every accepted value, field for field', () => {
    // Stated separately from the line above because it is the half
    // `docs/testing.md` names: "compare accepted values and rejection
    // behaviour". Both codecs accepting the same bytes and decoding them to
    // different fields is the failure this cross-check exists to catch, and it
    // would be invisible to a test that only counted acceptances.
    let compared = 0;
    for (const [index, mine] of ours.entries()) {
      const other = theirs[index];
      if (mine.verdict === 'accept' && other?.verdict === 'accept') {
        assert.equal(other.value, mine.value, `case ${mine.id}`);
        compared += 1;
      }
      if (mine.verdict === 'stream' && other?.verdict === 'stream') {
        assert.deepEqual(other.values, mine.values, `case ${mine.id}`);
        compared += mine.values.length;
      }
    }
    assert.ok(compared > 500, `only ${compared} values were compared`);
  });
});
