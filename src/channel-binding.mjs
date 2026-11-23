/**
 * Channel binding for the wsh authentication transcript (wsh #119).
 *
 * `buildTranscript()` has always had a `channel_binding` slot; nothing filled it, so a client's signature said
 * nothing about WHICH connection it was made over. An intermediary that terminates the client's connection and
 * opens its own to the host could pass a genuine challenge through and get the client's signature back
 * (the same limit the README states for host keys on `ws://`).
 *
 * The binding is a SHA-256 over what the two ends of the connection both know, each part tagged with its kind:
 *
 *   binding = SHA-256( "wsh-channel-binding-v1\0" || for each present kind, in the order below: lp(kind) || lp(value) )
 *
 *   kind           value                                                          who can supply it
 *   cert-hash      the 32-byte SHA-256 of the WebTransport certificate pinned     client with exactly one
 *                  through `serverCertificateHashes`                              `serverCertificateHashes` entry; host
 *   host           the raw 32-byte Ed25519 host key the client saw prove           client that verified the host's
 *                  possession (so a relay presenting its own key binds to THAT)   key proof; host with a `hostKey`
 *   tls-exporter   32 bytes of TLS keying material, label                          Node on both ends over TLS (the
 *                  "EXPORTER-wsh-channel-binding", empty context (RFC 5705/8446)   `ws` package); never a browser
 *
 * With no kind present the binding is the EMPTY byte string -- exactly what the transcript carried before, so a
 * peer that knows nothing of this still interoperates.
 *
 * Negotiation, all by feature string (no new wire field):
 *   - a host that can bind a kind lists `channel-binding:<kind>` in `ServerHello.features`; a host that REQUIRES a
 *     binding also lists `channel-binding-required`;
 *   - the client binds every kind that the host offers and it can supply, and signs that;
 *   - the host recomputes the binding over each non-empty combination of the kinds it offers (the client may lack
 *     one, a browser lacks `tls-exporter`) and accepts the signature if one matches -- the empty binding only if the
 *     host does not require one. A host that requires a binding also requires its named kinds, when it names any.
 *   - a client that must not authenticate unbound (`requireChannelBinding`) refuses when it ends up with none, which
 *     also defeats an intermediary that strips the host's `channel-binding:*` features.
 */

const enc = new TextEncoder();
const LABEL = enc.encode('wsh-channel-binding-v1\0');

export const CHANNEL_BINDING_PREFIX = 'channel-binding:';
export const CHANNEL_BINDING_REQUIRED_FEATURE = 'channel-binding-required';
/** TLS exporter label (RFC 5705 / RFC 8446 section 7.5) and length. */
export const TLS_EXPORTER_LABEL = 'EXPORTER-wsh-channel-binding';
export const TLS_EXPORTER_LENGTH = 32;
/** Canonical order of the kinds inside the hash. */
export const CHANNEL_BINDING_KINDS = Object.freeze(['cert-hash', 'host', 'tls-exporter']);

const lp = (bytes) => {
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length);
  out.set(bytes, 4);
  return out;
};

/**
 * @param {Record<string, Uint8Array>} values - kind -> value; unknown kinds and absent ones are ignored
 * @returns {Promise<Uint8Array>} 32 bytes, or an empty array when no kind is present
 */
export async function computeChannelBinding(values) {
  const parts = [LABEL];
  for (const kind of CHANNEL_BINDING_KINDS) {
    const v = values?.[kind];
    if (v instanceof Uint8Array && v.length) parts.push(lp(enc.encode(kind)), lp(v));
  }
  if (parts.length === 1) return new Uint8Array(0);
  const all = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) { all.set(p, off); off += p.length; }
  return new Uint8Array(await crypto.subtle.digest('SHA-256', all));
}

/** The kinds a `ServerHello.features` list offers, in canonical order. */
export function offeredKinds(features) {
  const set = new Set();
  for (const f of features ?? []) if (typeof f === 'string' && f.startsWith(CHANNEL_BINDING_PREFIX)) set.add(f.slice(CHANNEL_BINDING_PREFIX.length));
  return CHANNEL_BINDING_KINDS.filter((k) => set.has(k));
}

/** Does `features` say the host requires a channel binding? */
export const requiresBinding = (features) => (features ?? []).includes(CHANNEL_BINDING_REQUIRED_FEATURE);

/** The `ServerHello` feature strings for what a host can bind (and, optionally, that it requires one). */
export function bindingFeatures(kinds, { required = false } = {}) {
  return [...kinds.map((k) => CHANNEL_BINDING_PREFIX + k), ...(required ? [CHANNEL_BINDING_REQUIRED_FEATURE] : [])];
}

/**
 * The client side: bind everything offered that this client can supply.
 * @param {string[]} serverFeatures
 * @param {Record<string, Uint8Array | null | undefined>} available - what the client holds, by kind
 * @returns {Promise<{ binding: Uint8Array, kinds: string[] }>}
 */
export async function clientChannelBinding(serverFeatures, available) {
  const kinds = offeredKinds(serverFeatures).filter((k) => available?.[k] instanceof Uint8Array && available[k].length);
  const values = {};
  for (const k of kinds) values[k] = available[k];
  return { binding: await computeChannelBinding(values), kinds };
}

/**
 * The host side: every binding a client might legitimately have signed, as `{ binding, kinds }`.
 * @param {Record<string, Uint8Array[]>} held - the kinds this host can compute, each with its (usually one) value;
 *   several for `cert-hash` while a certificate rotates
 * @param {{ required: false | true | string[] }} policy - `true`: a non-empty binding; an array: those kinds too
 * @returns {Promise<{ binding: Uint8Array, kinds: string[] }[]>}
 */
export async function acceptableBindings(held, { required = false } = {}) {
  const kinds = CHANNEL_BINDING_KINDS.filter((k) => held[k]?.length);
  const must = Array.isArray(required) ? required : [];
  const out = [];
  const subsets = [];
  for (let mask = 0; mask < (1 << kinds.length); mask++) subsets.push(kinds.filter((_, i) => mask & (1 << i)));
  for (const subset of subsets) {
    if (subset.length === 0 && required) continue;
    if (!must.every((k) => subset.includes(k))) continue;
    // Expand alternatives (a rotating certificate has two hashes).
    let combos = [{}];
    for (const k of subset) combos = combos.flatMap((c) => held[k].map((v) => ({ ...c, [k]: v })));
    for (const values of combos) out.push({ binding: await computeChannelBinding(values), kinds: subset });
  }
  return out;
}

const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
/** @returns {boolean} whether `binding` is one of `acceptable` */
export const bindingAcceptable = (acceptable, binding) => acceptable.some((a) => eq(a.binding, binding));
