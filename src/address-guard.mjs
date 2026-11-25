/**
 * `@johnhenry/wsh/address-guard` -- the destination-address guard of the gateway, as an entry point of its own (Node).
 *
 * A host that dials where a client asks must check WHERE the connection goes, not only what the destination was called:
 * a name can resolve to a loopback, private, link-local or cloud-metadata address, and it can resolve to one address for
 * the check and another for the connection. This module is the one tested implementation the gateway of
 * `@johnhenry/wsh/server` uses:
 *
 *  - `classifyAddress(ip)` and `isPublicAddress(ip)`: what kind of address is this (pure; also fine in a browser, and a
 *    bundler can take them alone: they come from `address-class.mjs`, which imports nothing).
 *  - `checkAddress(ip, policy)`: may it be dialled under a policy (`allowPrivate`, `allow`, `deny`).
 *  - `resolveChecked(name, options)`: resolve a name ONCE and return the addresses that pass.
 *  - `dialChecked(host, port, options)`: resolve once, check, and connect a TCP socket to an address that passed (never to
 *    the name, so it is never resolved a second time). Returns the socket and the address actually dialled.
 *  - `dialUdpChecked(host, port, options)`: the same for a datagram socket, `connect()`ed to the checked address so the
 *    kernel drops every datagram that does not come from that address and port.
 *
 * The node modules are loaded on first use, so importing this module for the classifier alone costs nothing.
 */

import { parseIp, compileAddressPolicy, checkCompiled } from './address-class.mjs';

export { isPublicAddress, classifyAddress, ADDRESS_CLASSES, checkAddress } from './address-class.mjs';

let netModule = null;
let dnsModule = null;
let dgramModule = null;
// The specifiers are held in variables so that a bundler for a browser, which resolves every literal `import('node:...')`
// and fails on it, can still take the classifier from this entry (`import { isPublicAddress } from '@johnhenry/wsh/address-guard'`)
// without the dial functions it does not use. In Node the three imports are ordinary.
const NET = 'node:net';
const DNS = 'node:dns/promises';
const DGRAM = 'node:dgram';
const loadNet = async () => (netModule ??= (await import(NET)).default);
const loadDns = async () => (dnsModule ??= (await import(DNS)).default);
const loadDgram = async () => (dgramModule ??= (await import(DGRAM)).default);

const DEFAULT_TIMEOUT_MS = 15_000;

/**
 * What went wrong, in `code`: `ADDRESS_REFUSED` (every answer, or with `refuseMixed` any answer, is refused by the policy;
 * `refused` lists `{ address, class }`), `NAME_NOT_FOUND`, `LOOKUP_FAILED`, `CONNECTION_REFUSED`, `UNREACHABLE`, `TIMEOUT`,
 * `ABORTED`. The error that caused it, when there is one, is `cause`.
 */
export class AddressGuardError extends Error {
  /**
   * @param {string} code
   * @param {string} message
   * @param {{ refused?: Array<{ address: string, class: string }>, cause?: unknown }} [extra]
   */
  constructor(code, message, { refused, cause } = {}) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'AddressGuardError';
    this.code = code;
    if (refused) {
      this.refused = refused;
      this.refusedAddresses = refused.map((r) => r.address);
    }
  }
}

const aborted = () => new AddressGuardError('ABORTED', 'aborted');
const timedOut = (what) => new AddressGuardError('TIMEOUT', what);

/** Validate the options shared by every function here, once. */
function prepare(options) {
  const o = options ?? {};
  if (typeof o !== 'object') throw new TypeError('options must be an object');
  const family = o.family ?? 0;
  if (family !== 0 && family !== 4 && family !== 6) throw new TypeError('family must be 0, 4 or 6');
  const timeoutMs = o.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new TypeError('timeoutMs must be a positive number');
  if (o.lookup !== undefined && typeof o.lookup !== 'function') throw new TypeError('lookup must be a function');
  return {
    policy: compileAddressPolicy(o),
    family,
    signal: o.signal,
    lookup: o.lookup,
    refuseMixed: o.refuseMixed === true,
    deadline: Date.now() + timeoutMs,
  };
}

function checkTarget(host, port) {
  if (typeof host !== 'string' || !host) throw new TypeError('host must be a non-empty string');
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new TypeError('port must be an integer from 1 to 65535');
}

/** `work` settled, or the deadline passed, or the signal fired: whichever comes first. */
function bounded(work, { signal, deadline }, what) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) { reject(aborted()); return; }
    let done = false;
    const finish = (fn, v) => { if (done) return; done = true; clearTimeout(timer); signal?.removeEventListener('abort', onAbort); fn(v); };
    const onAbort = () => finish(reject, aborted());
    const timer = setTimeout(() => finish(reject, timedOut(what)), Math.max(deadline - Date.now(), 0));
    timer.unref?.();
    signal?.addEventListener('abort', onAbort, { once: true });
    Promise.resolve(work).then((v) => finish(resolve, v), (e) => finish(reject, e));
  });
}

const lookupError = (e) => {
  if (e instanceof AddressGuardError) return e;
  if (e?.code === 'ENOTFOUND' || e?.code === 'ENODATA') return new AddressGuardError('NAME_NOT_FOUND', 'name not found', { cause: e });
  return new AddressGuardError('LOOKUP_FAILED', String(e?.message ?? e), { cause: e });
};

/** The answers of the resolver as strings; an IP literal is its own answer and is not looked up. */
async function answersFor(name, o) {
  const literal = parseIp(name);
  if (literal) return [name.trim()];
  const lookup = o.lookup ?? (async (n, opts) => (await loadDns()).lookup(n, { ...opts, all: true, verbatim: true }));
  let found;
  try { found = await bounded(lookup(name, { family: o.family }), o, 'name lookup timed out'); } catch (e) { throw lookupError(e); }
  if (!Array.isArray(found)) throw new AddressGuardError('LOOKUP_FAILED', 'the resolver returned no list');
  return found.map((a) => (typeof a === 'string' ? a : a?.address));
}

async function resolveWith(name, o) {
  if (typeof name !== 'string' || !name) throw new TypeError('name must be a non-empty string');
  const all = (await answersFor(name, o)).filter((a) => typeof a === 'string');
  const wanted = o.family ? all.filter((a) => { const ip = parseIp(a); return !ip || ip.v === o.family; }) : all;
  if (wanted.length === 0) throw new AddressGuardError('NAME_NOT_FOUND', 'name not found');
  const permitted = [];
  const refused = [];
  for (const address of wanted) {
    const c = checkCompiled(address, o.policy);
    if (c.permitted) permitted.push({ address, family: parseIp(address).v, class: c.class });
    else refused.push({ address, class: c.class });
  }
  if (permitted.length === 0 || (o.refuseMixed && refused.length)) {
    const why = refused.map((r) => `${r.address} (${r.class})`).join(', ');
    throw new AddressGuardError('ADDRESS_REFUSED', `the address this name resolves to is not permitted by the address policy: ${why}`, { refused });
  }
  return permitted;
}

/**
 * Resolve `name` ONCE and return only the addresses the policy permits, in the order the resolver gave them. An IP literal
 * is checked as it is. Nothing that then connects should use the name again: connect to one of these addresses.
 *
 * @param {string} name
 * @param {{
 *   allowPrivate?: boolean, allow?: string[], deny?: string[], family?: 0 | 4 | 6, timeoutMs?: number, signal?: AbortSignal,
 *   refuseMixed?: boolean, lookup?: (name: string, options: { family: 0 | 4 | 6 }) => Promise<Array<string | { address: string }>>,
 * }} [options]
 * @returns {Promise<Array<{ address: string, family: 4 | 6, class: string }>>}
 */
export async function resolveChecked(name, options) {
  return resolveWith(name, prepare(options));
}

const connectError = (e) => {
  const code = e?.code === 'ECONNREFUSED' ? 'CONNECTION_REFUSED' : e?.code === 'ENOTFOUND' || e?.code === 'EAI_AGAIN' ? 'NAME_NOT_FOUND' : 'UNREACHABLE';
  return new AddressGuardError(code, e?.code === 'ENOTFOUND' ? 'name not found' : String(e?.message ?? e), { cause: e });
};

/** Connect to ONE address (no name lookup happens: it is already resolved and checked). */
async function connectAddress(address, port, o) {
  const net = await loadNet();
  return new Promise((resolve, reject) => {
    if (o.signal?.aborted) { reject(aborted()); return; }
    const s = net.connect({ host: address, port });
    const cleanup = () => { clearTimeout(timer); o.signal?.removeEventListener('abort', onAbort); };
    const onAbort = () => { cleanup(); s.destroy(); reject(aborted()); };
    const onError = (e) => { cleanup(); reject(connectError(e)); };
    const timer = setTimeout(() => { cleanup(); s.destroy(); reject(timedOut('connect timed out')); }, Math.max(o.deadline - Date.now(), 1));
    timer.unref?.();
    o.signal?.addEventListener('abort', onAbort, { once: true });
    s.once('connect', () => { cleanup(); s.off('error', onError); resolve(s); });
    s.once('error', onError);
  });
}

/**
 * Resolve `host` once, keep only the addresses the policy permits, and connect a TCP socket to the first that answers: the
 * connection is made to the address that was checked, never to the name. `host` may be an IP literal (checked as it is).
 * Rejects with an `AddressGuardError` (`ADDRESS_REFUSED` when the policy refuses every address; nothing is dialled then).
 * A bad `host` or `port` is a `TypeError`. `timeoutMs` (15 s) bounds the lookup and the connects together.
 *
 * @param {string} host
 * @param {number} port
 * @param {Parameters<typeof resolveChecked>[1] & {}} [options]
 * @returns {Promise<{ socket: import('node:net').Socket, address: string, family: 4 | 6, class: string }>}
 */
export async function dialChecked(host, port, options) {
  checkTarget(host, port);
  const o = prepare(options);
  const candidates = await resolveWith(host, o);
  let last;
  for (const c of candidates) {
    if (o.deadline - Date.now() <= 0) break;
    try { return { socket: await connectAddress(c.address, port, o), address: c.address, family: c.family, class: c.class }; } catch (e) {
      if (e.code === 'ABORTED') throw e;
      last = e;
    }
  }
  throw last ?? timedOut('connect timed out');
}

/**
 * The same for a UDP socket: resolve `host` once, check, and return a datagram socket `connect()`ed to a checked address.
 * A connected UDP socket receives datagrams only from that address and port (the kernel drops the rest), so the destination
 * cannot be made a relay to others, and `send(payload)` needs no address. The caller owns the socket (`error`, `message`,
 * `close`).
 *
 * @param {string} host
 * @param {number} port
 * @param {Parameters<typeof resolveChecked>[1] & {}} [options]
 * @returns {Promise<{ socket: import('node:dgram').Socket, address: string, family: 4 | 6, class: string }>}
 */
export async function dialUdpChecked(host, port, options) {
  checkTarget(host, port);
  const o = prepare(options);
  const candidates = await resolveWith(host, o);
  const dgram = await loadDgram();
  let last;
  for (const c of candidates) {
    if (o.signal?.aborted) throw aborted();
    const socket = dgram.createSocket(c.family === 6 ? 'udp6' : 'udp4');
    try {
      await new Promise((resolve, reject) => { socket.once('error', reject); socket.connect(port, c.address, () => { socket.off('error', reject); resolve(); }); });
      if (o.signal?.aborted) { socket.close(); throw aborted(); }
      return { socket, address: c.address, family: c.family, class: c.class };
    } catch (e) {
      try { socket.close(); } catch { /* not open */ }
      if (e instanceof AddressGuardError) throw e;
      last = connectError(e);
    }
  }
  throw last ?? timedOut('connect timed out');
}
