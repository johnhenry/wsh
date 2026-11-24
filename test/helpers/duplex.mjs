// Two `createDuplexPeer`s joined in memory: what one sends, the other receives (asynchronously, after a structured clone, so nothing is shared).
// The bare transport of the objects suite: no wsh anywhere.
import { createDuplexPeer } from '../../src/objects-core.mjs';

export function createDuplexPair(options = {}) {
  let a; let b;
  a = createDuplexPeer({ ...options, send: (m) => { const copy = structuredClone(m); queueMicrotask(() => b.receive(copy)); } });
  b = createDuplexPeer({ ...options, send: (m) => { const copy = structuredClone(m); queueMicrotask(() => a.receive(copy)); } });
  return [a, b];
}
