// A fixed-seed xorshift64 and a byte mutator, shared by the CBOR fuzz tests (#317): the same mutations on every run, on every machine.
export function xorshift(seed) {
  let s = BigInt.asUintN(64, seed);
  const next = () => { s ^= BigInt.asUintN(64, s << 13n); s ^= s >> 7n; s ^= BigInt.asUintN(64, s << 17n); return s; };
  return { next, below: (n) => Number(next() % BigInt(n)) };
}

/** One to four edits of `src`: flip a bit, replace, delete or insert a byte, truncate, or append. */
export function mutate(rng, src) {
  let b = Array.from(src);
  const edits = 1 + rng.below(3);
  for (let k = 0; k < edits; k++) {
    const op = rng.below(6);
    if (op === 0 && b.length) b[rng.below(b.length)] ^= 1 << rng.below(8);
    else if (op === 1 && b.length) b[rng.below(b.length)] = rng.below(256);
    else if (op === 2 && b.length) b.splice(rng.below(b.length), 1);
    else if (op === 3) b.splice(rng.below(b.length + 1), 0, rng.below(256));
    else if (op === 4 && b.length) b = b.slice(0, rng.below(b.length));
    else b.push(rng.below(256));
  }
  return Uint8Array.from(b);
}

/**
 * A random value the JS encoder can write, drawn from `rng`: nested maps and arrays, strings (including multi-byte and astral), byte strings,
 * integers across every head size and up to the 64-bit limits (a BigInt past 2^53), fractional floats of every width, NaN, infinities and -0.
 * No integral float is generated: the JS encoder writes an integral number as an integer, and a Rust f64 of the same value is a float.
 */
export function randomValue(rng, depth = 0) {
  const kind = rng.below(depth > 3 ? 9 : 12);
  switch (kind) {
    case 0: return null;
    case 1: return rng.below(2) === 0;
    case 2: return [0, 1, 23, 24, 255, 256, 65535, 65536, 2 ** 32 - 1, 2 ** 32, 2 ** 53 - 1][rng.below(11)] * (rng.below(2) ? 1 : -1);
    case 3: return [2n ** 53n, 2n ** 53n + 1n, 2n ** 63n, 2n ** 64n - 1n, -(2n ** 53n) - 1n, -(2n ** 63n), -(2n ** 64n)][rng.below(7)];
    case 4: { // a float of a chosen width: a half value, a single value, or a double that is neither
      const w = rng.below(3);
      const frac = (rng.below(2000) + 1) / 1024 + 0.0009765625 * 0; // k/1024 + ...: exact in a half for small k
      if (w === 0) return (rng.below(1023) + 0.5) / 512 + 1;
      if (w === 1) return Math.fround((rng.below(1_000_000) + 0.5) / 4096 + 3);
      return frac + Math.PI * (rng.below(1000) + 1);
    }
    case 5: return [NaN, Infinity, -Infinity, -0, 1e300, -1e-300, 5e-324, 2 ** 64, -(2 ** 70), 65504.5][rng.below(10)];
    case 6: return ['', 'a', 'é', '世界', '\u{1f600}', 'x'.repeat(rng.below(40)), 'k'.repeat(24)][rng.below(7)];
    case 7: return Uint8Array.from({ length: rng.below(30) }, () => rng.below(256));
    case 8: return rng.below(1000);
    case 9: return Array.from({ length: rng.below(5) }, () => randomValue(rng, depth + 1));
    default: { // a map: keys of different lengths and UTF-8 byte orders, in an arbitrary insertion order
      const pool = ['type', 'id', 'a', 'b', 'zz', 'aa', 'é', 'ā', '世', '\u{1f600}', 'longer key', 'k'.repeat(30), '', '10', '2', 'session_id'];
      const o = {};
      for (let i = rng.below(7); i > 0; i--) o[pool[rng.below(pool.length)]] = randomValue(rng, depth + 1);
      return o;
    }
  }
}
