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
