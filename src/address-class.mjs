/**
 * The destination-address classifier of the gateway: what kind of address is this IP, and may a host dial it on a
 * client's behalf without an explicit rule? "Public" means globally routable unicast. Everything else has a class of
 * its own (`private`, `loopback`, `link-local`, `metadata`, ...) so a caller can say WHY an address was refused.
 *
 * An IPv6 address that merely wraps an IPv4 one is classified as the IPv4 address it wraps, because that is where a
 * translator or tunnel would send the packet: an IPv4-mapped address (`::ffff:127.0.0.1`), a NAT64 address
 * (`64:ff9b::7f00:1`) and a 6to4 address (`2002:7f00:1::`). A Teredo address (`2001::/32`) hides its server and client
 * addresses behind an obfuscation and is only ever reached through a relay the dialling host does not run, so it is
 * refused whatever it wraps (`teredo`). The deprecated IPv4-compatible form (`::127.0.0.1`) is `reserved`, and so is the
 * local-use NAT64 prefix (`64:ff9b:1::/48`).
 *
 * Pure JavaScript with no `node:*` import, so a bundler can take this file alone (it is part of the browser-safe memory
 * host's import graph). It parses text strictly: it is given the addresses a resolver RETURNED, never a name or a number
 * a client wrote, so the odd spellings `getaddrinfo` accepts (`2130706433`, `0x7f.1`) never reach it as an address.
 */

/** @returns {Uint8Array | null} 4 bytes */
function parseV4(text) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (!m) return null;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const part = m[i + 1];
    if (part.length > 1 && part[0] === '0') return null; // no leading zeros: "010" is octal to some parsers
    const n = Number(part);
    if (n > 255) return null;
    out[i] = n;
  }
  return out;
}

/** @returns {Uint8Array | null} 16 bytes */
function parseV6(text) {
  if (text.includes('%')) return null; // a zone id is local to the host's interfaces: never public
  let s = text;
  let tail = null;
  const lastColon = s.lastIndexOf(':');
  if (lastColon !== -1 && s.includes('.', lastColon)) {
    const v4 = parseV4(s.slice(lastColon + 1));
    if (!v4) return null;
    tail = v4;
    s = `${s.slice(0, lastColon + 1)}0:0`; // two groups stand in for the dotted tail
  }
  const dbl = s.split('::');
  if (dbl.length > 2) return null;
  const groups = (part) => (part === '' ? [] : part.split(':'));
  const head = groups(dbl[0]);
  const rest = dbl.length === 2 ? groups(dbl[1]) : [];
  const all = [...head, ...rest];
  if (all.some((g) => !/^[0-9a-fA-F]{1,4}$/.test(g))) return null;
  let words;
  if (dbl.length === 2) {
    const fill = 8 - head.length - rest.length;
    if (fill < 1) return null;
    words = [...head, ...Array(fill).fill('0'), ...rest];
  } else {
    if (head.length !== 8) return null;
    words = head;
  }
  const out = new Uint8Array(16);
  words.forEach((w, i) => { const n = parseInt(w, 16); out[2 * i] = n >> 8; out[2 * i + 1] = n & 255; });
  if (tail) out.set(tail, 12);
  return out;
}

/**
 * @param {string} text
 * @returns {{ v: 4 | 6, bytes: Uint8Array } | null}
 */
export function parseIp(text) {
  if (typeof text !== 'string') return null;
  const t = text.trim();
  const v4 = parseV4(t);
  if (v4) return { v: 4, bytes: v4 };
  const v6 = parseV6(t);
  return v6 ? { v: 6, bytes: v6 } : null;
}

/**
 * Every class `classifyAddress` can return. `public` is the only one a host dials without a rule.
 * @type {readonly string[]}
 */
export const ADDRESS_CLASSES = Object.freeze([
  'public', 'invalid', 'unspecified', 'loopback', 'private', 'unique-local', 'link-local', 'metadata', 'carrier-nat',
  'documentation', 'benchmarking', 'multicast', 'teredo', 'reserved',
]);

/** [address, prefix bits, class], first match wins: the single addresses of cloud metadata services come before their blocks. */
const V4_RULES = [
  ['169.254.169.254', 32, 'metadata'], // AWS, GCP, Azure, DigitalOcean, OpenStack instance metadata
  ['169.254.170.2', 32, 'metadata'], // AWS ECS task metadata
  ['100.100.100.200', 32, 'metadata'], // Alibaba Cloud
  ['192.0.0.192', 32, 'metadata'], // Oracle Cloud
  ['168.63.129.16', 32, 'metadata'], // Azure's platform endpoint (a routable address that only exists inside the platform)
  ['0.0.0.0', 8, 'unspecified'], ['10.0.0.0', 8, 'private'], ['100.64.0.0', 10, 'carrier-nat'], ['127.0.0.0', 8, 'loopback'],
  ['169.254.0.0', 16, 'link-local'], ['172.16.0.0', 12, 'private'], ['192.0.0.0', 24, 'reserved'], ['192.0.2.0', 24, 'documentation'],
  ['192.88.99.0', 24, 'reserved'], ['192.168.0.0', 16, 'private'], ['198.18.0.0', 15, 'benchmarking'],
  ['198.51.100.0', 24, 'documentation'], ['203.0.113.0', 24, 'documentation'], ['224.0.0.0', 4, 'multicast'], ['240.0.0.0', 4, 'reserved'],
].map(([a, bits, cls]) => ({ bytes: parseV4(a), bits, cls }));

/** Do the first `bits` bits of `a` and `b` agree? */
function samePrefix(a, b, bits) {
  const whole = bits >> 3;
  for (let i = 0; i < whole; i++) if (a[i] !== b[i]) return false;
  const rem = bits & 7;
  if (!rem) return true;
  const mask = (0xff << (8 - rem)) & 0xff;
  return (a[whole] & mask) === (b[whole] & mask);
}

function v4Class(b) {
  for (const r of V4_RULES) if (samePrefix(b, r.bytes, r.bits)) return r.cls;
  return 'public';
}

const zero = (b, from, to) => { for (let i = from; i < to; i++) if (b[i] !== 0) return false; return true; };

/** The IPv4 address an IPv6 one wraps (mapped, NAT64, 6to4), or null if it wraps none. */
function embeddedV4(b) {
  if (zero(b, 0, 10) && b[10] === 0xff && b[11] === 0xff) return b.subarray(12, 16); // ::ffff:a.b.c.d
  if (b[0] === 0 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b && zero(b, 4, 12)) return b.subarray(12, 16); // 64:ff9b::/96
  if (b[0] === 0x20 && b[1] === 0x02) return b.subarray(2, 6); // 2002::/16 (6to4)
  return null;
}

function v6Class(b) {
  const inner = embeddedV4(b);
  if (inner) return v4Class(inner);
  if (zero(b, 0, 12)) { // ::/96: unspecified, loopback, the deprecated IPv4-compatible form
    if (zero(b, 12, 16)) return 'unspecified';
    return zero(b, 12, 15) && b[15] === 1 ? 'loopback' : 'reserved';
  }
  if (b[0] === 0xfd && b[1] === 0x00 && b[2] === 0x0e && b[3] === 0xc2 && zero(b, 4, 14) && b[14] === 0x02 && b[15] === 0x54) return 'metadata'; // fd00:ec2::254, AWS over IPv6
  if ((b[0] & 0xfe) === 0xfc) return 'unique-local'; // fc00::/7
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return 'link-local'; // fe80::/10
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0xc0) return 'private'; // fec0::/10, the deprecated site-local block
  if (b[0] === 0xff) return 'multicast';
  if ((b[0] & 0xe0) !== 0x20) return 'reserved'; // only 2000::/3 is global unicast
  if (b[0] === 0x20 && b[1] === 0x01) {
    if (b[2] === 0 && b[3] === 0) return 'teredo'; // 2001::/32
    if (b[2] === 0 && b[3] === 2 && b[4] === 0 && b[5] === 0) return 'benchmarking'; // 2001:2::/48
    if (b[2] <= 0x01) return 'reserved'; // 2001::/23: IETF protocol assignments, ORCHID, ...
    if (b[2] === 0x0d && b[3] === 0xb8) return 'documentation'; // 2001:db8::/32
  }
  if (b[0] === 0x3f && b[1] === 0xff && (b[2] & 0xf0) === 0) return 'documentation'; // 3fff::/20
  return 'public';
}

/**
 * What kind of address is `text` (as a resolver returns it)? One of `ADDRESS_CLASSES`: `public`, or the reason it is
 * not (`loopback`, `private`, `link-local`, `metadata`, ...). Anything that is not an IP address is `invalid`.
 * @param {unknown} text
 * @returns {string}
 */
export function classifyAddress(text) {
  const ip = parseIp(text);
  if (!ip) return 'invalid';
  return ip.v === 4 ? v4Class(ip.bytes) : v6Class(ip.bytes);
}

/** Is this address (text, as a resolver returns it) globally routable unicast, wrapped forms included? */
export function isPublicAddress(text) {
  return classifyAddress(text) === 'public';
}

/**
 * A CIDR block or a single address: `10.0.0.0/8`, `127.0.0.1`, `::1`, `fd00::/8`.
 * @returns {{ v: 4 | 6, bytes: Uint8Array, bits: number } | null}
 */
export function parseCidr(text) {
  if (typeof text !== 'string') return null;
  const [addr, len, ...extra] = text.trim().split('/');
  if (extra.length) return null;
  const ip = parseIp(addr);
  if (!ip) return null;
  const max = ip.v === 4 ? 32 : 128;
  let bits = max;
  if (len !== undefined) {
    if (!/^\d{1,3}$/.test(len)) return null;
    bits = Number(len);
    if (bits > max) return null;
  }
  return { v: ip.v, bytes: ip.bytes, bits };
}

/** An IPv4-mapped IPv6 address is compared as the IPv4 address it wraps. */
function normalized(ip) {
  if (ip.v === 6 && zero(ip.bytes, 0, 10) && ip.bytes[10] === 0xff && ip.bytes[11] === 0xff) return { v: 4, bytes: ip.bytes.subarray(12, 16) };
  return ip;
}

/** Is the parsed address inside the parsed CIDR block? A mapped IPv6 address is tested as the IPv4 one it wraps. */
function ipInCidr(ip, cidr) {
  const a = normalized(ip);
  const c = normalized({ v: cidr.v, bytes: cidr.bytes });
  const bits = cidr.v === 6 && c.v === 4 ? cidr.bits - 96 : cidr.bits;
  if (a.v !== c.v || bits < 0) return false;
  return samePrefix(a.bytes, c.bytes, bits);
}

/** Is `text` inside the CIDR block (see `parseCidr`)? A mapped IPv6 address is tested as the IPv4 one it wraps. */
export function addressInCidr(text, cidr) {
  const ip = parseIp(text);
  if (!ip || !cidr) return false;
  return ipInCidr(ip, cidr);
}

/** Do two address strings name the same address (a mapped IPv6 address equals the IPv4 one it wraps)? */
export function sameAddress(a, b) {
  const x = parseIp(a); const y = parseIp(b);
  if (!x || !y) return false;
  const nx = normalized(x); const ny = normalized(y);
  return nx.v === ny.v && samePrefix(nx.bytes, ny.bytes, nx.v === 4 ? 32 : 128);
}

// ── The policy ──────────────────────────────────────────────────────

/** The classes `allowPrivate: true` lets through: private-network space. Everything else needs an `allow` entry. */
const PRIVATE_NETWORK_CLASSES = new Set(['private', 'loopback', 'link-local', 'unique-local', 'carrier-nat']);

/**
 * @typedef {object} AddressPolicy
 * @property {boolean} [allowPrivate=false]  let the private-network classes through (`private`, `loopback`, `link-local`, `unique-local`, `carrier-nat`); never `metadata`, `unspecified`, `multicast`, `reserved`, `documentation`, `benchmarking`, `teredo`
 * @property {Array<string | { v: 4 | 6, bytes: Uint8Array, bits: number }>} [allow=[]]  CIDR blocks or addresses that are permitted whatever their class
 * @property {Array<string | { v: 4 | 6, bytes: Uint8Array, bits: number }>} [deny=[]]  CIDR blocks or addresses that are always refused, public ones included; wins over `allow` and `allowPrivate`
 */

/**
 * Validate a policy once. A bad entry is a TypeError, never a silently open check.
 * @param {AddressPolicy | undefined} policy
 * @returns {{ allowPrivate: boolean, allow: object[], deny: object[] }}
 */
export function compileAddressPolicy(policy) {
  if (policy === undefined || policy === null) policy = {};
  if (typeof policy !== 'object') throw new TypeError('the address policy must be an options object');
  if (policy.allowPrivate !== undefined && typeof policy.allowPrivate !== 'boolean') throw new TypeError('allowPrivate must be a boolean (list CIDR blocks in `allow`)');
  const list = (v, what) => {
    if (v === undefined) return [];
    if (!Array.isArray(v)) throw new TypeError(`${what} must be an array of CIDR blocks or addresses`);
    return v.map((r) => {
      const c = typeof r === 'string' ? parseCidr(r) : (r && typeof r === 'object' && r.bytes instanceof Uint8Array && (r.v === 4 || r.v === 6) && Number.isInteger(r.bits) ? r : null);
      if (!c) throw new TypeError(`${what}: ${JSON.stringify(r)} is not an address or CIDR block`);
      return c;
    });
  };
  return { allowPrivate: policy.allowPrivate === true, allow: list(policy.allow, 'allow'), deny: list(policy.deny, 'deny') };
}

/**
 * The check on one address with an already compiled policy.
 * @returns {{ permitted: boolean, class: string, reason?: 'class' | 'deny' }}
 */
export function checkCompiled(address, compiled) {
  const ip = parseIp(address);
  if (!ip) return { permitted: false, class: 'invalid', reason: 'class' };
  const cls = ip.v === 4 ? v4Class(ip.bytes) : v6Class(ip.bytes);
  if (compiled.deny.length) {
    const wrapped = ip.v === 6 ? embeddedV4(ip.bytes) : null; // a denied IPv4 block is denied in its wrapped forms too
    for (const c of compiled.deny) {
      if (ipInCidr(ip, c) || (wrapped && ipInCidr({ v: 4, bytes: wrapped }, c))) return { permitted: false, class: cls, reason: 'deny' };
    }
  }
  if (cls === 'public') return { permitted: true, class: cls };
  if (compiled.allow.some((c) => ipInCidr(ip, c))) return { permitted: true, class: cls };
  if (compiled.allowPrivate && PRIVATE_NETWORK_CLASSES.has(cls)) return { permitted: true, class: cls };
  return { permitted: false, class: cls, reason: 'class' };
}

/**
 * May a host dial this address? Public addresses, the classes `allowPrivate` names, and `allow` entries; never a `deny` entry.
 * @param {unknown} address
 * @param {AddressPolicy} [policy]
 * @returns {{ permitted: boolean, class: string, reason?: 'class' | 'deny' }}
 */
export function checkAddress(address, policy) {
  return checkCompiled(address, compileAddressPolicy(policy));
}
