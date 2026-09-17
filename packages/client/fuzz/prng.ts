/**
 * A deterministic pseudo-random generator for the shared corpus.
 *
 * `splitmix64`, written out. The generator must be reproducible from its seed
 * on any host and in any Node version, so `Math.random` is unusable and so is
 * anything whose implementation may change under us. `splitmix64` is four
 * lines of arithmetic with a published constant set, and a failing case is
 * reproduced by re-running the generator with the seed the corpus records.
 */

const MASK = (1n << 64n) - 1n;

export class Prng {
  private state: bigint;

  constructor(seed: bigint) {
    this.state = seed & MASK;
  }

  /** The next 64-bit value. */
  next(): bigint {
    this.state = (this.state + 0x9e3779b97f4a7c15n) & MASK;
    let z = this.state;
    z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & MASK;
    z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & MASK;
    return z ^ (z >> 31n);
  }

  /** A value in `[0, bound)`. */
  below(bound: number): number {
    if (bound <= 0) {
      throw new RangeError('bound must be positive');
    }
    return Number(this.next() % BigInt(bound));
  }

  /** One element of `values`, which must not be empty. */
  pick<T>(values: readonly T[]): T {
    const chosen = values[this.below(values.length)];
    if (chosen === undefined) {
      throw new RangeError('pick from an empty array');
    }
    return chosen;
  }

  /** True with probability `numerator / denominator`. */
  chance(numerator: number, denominator: number): boolean {
    return this.below(denominator) < numerator;
  }

  /** `count` random bytes. */
  bytes(count: number): Uint8Array {
    const out = new Uint8Array(count);
    for (let index = 0; index < count; index += 1) {
      out[index] = this.below(256);
    }
    return out;
  }
}
