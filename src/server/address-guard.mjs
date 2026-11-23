/**
 * The destination-address guard of the gateway: is an IP address one a host may dial on a client's behalf without
 * an explicit rule? "Public" here means globally routable unicast. Loopback, private (RFC 1918, ULA), link-local,
 * carrier-grade NAT, documentation, benchmarking, multicast and reserved ranges are NOT public, and neither is an
 * address that merely wraps one of those: an IPv4-mapped IPv6 address (`::ffff:127.0.0.1`), a NAT64 address
 * (`64:ff9b::7f00:1`), a 6to4 address (`2002:7f00:1::`) or an IPv4-compatible one (`::127.0.0.1`).
 *
 * Pure JavaScript with no `node:*` import (the gateway module is part of the browser-safe memory host's import
 * graph). It parses text strictly: it is given the addresses a resolver RETURNED, never a name or a number a client
 * wrote, so the odd spellings `getaddrinfo` accepts (`2130706433`, `0x7f.1`) never reach it as an address.
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

const V4_NON_PUBLIC = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
].map(([a, bits]) => ({ bytes: parseV4(a), bits }));

/** Do the first `bits` bits of `a` and `b` agree? */
function samePrefix(a, b, bits) {
  const whole = bits >> 3;
  for (let i = 0; i < whole; i++) if (a[i] !== b[i]) return false;
  const rem = bits & 7;
  if (!rem) return true;
  const mask = (0xff << (8 - rem)) & 0xff;
  return (a[whole] & mask) === (b[whole] & mask);
}

function v4Public(b) {
  return !V4_NON_PUBLIC.some((r) => samePrefix(b, r.bytes, r.bits));
}

const zero = (b, from, to) => { for (let i = from; i < to; i++) if (b[i] !== 0) return false; return true; };

/** The IPv4 address an IPv6 one wraps (mapped, NAT64, 6to4), or null if it wraps none. */
function embeddedV4(b) {
  if (zero(b, 0, 10) && b[10] === 0xff && b[11] === 0xff) return b.subarray(12, 16); // ::ffff:a.b.c.d
  if (b[0] === 0 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b && zero(b, 4, 12)) return b.subarray(12, 16); // 64:ff9b::/96
  if (b[0] === 0x20 && b[1] === 0x02) return b.subarray(2, 6); // 2002::/16 (6to4)
  return null;
}

/** Is this address (text, as a resolver returns it) globally routable unicast, wrapped forms included? */
export function isPublicAddress(text) {
  const ip = parseIp(text);
  if (!ip) return false;
  if (ip.v === 4) return v4Public(ip.bytes);
  const b = ip.bytes;
  const inner = embeddedV4(b);
  if (inner) return v4Public(inner);
  if (zero(b, 0, 12)) return false; // ::/96: unspecified, loopback, the deprecated IPv4-compatible form
  if ((b[0] & 0xe0) !== 0x20) return false; // only 2000::/3 is global unicast
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] <= 0x01) return false; // 2001::/23: IETF protocol assignments, Teredo, ORCHID...
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x0d && b[3] === 0xb8) return false; // 2001:db8::/32 documentation
  if (b[0] === 0x3f && b[1] === 0xff && (b[2] & 0xf0) === 0) return false; // 3fff::/20 documentation
  return true;
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

/** Is `text` inside the CIDR block (see `parseCidr`)? A mapped IPv6 address is tested as the IPv4 one it wraps. */
export function addressInCidr(text, cidr) {
  const ip = parseIp(text);
  if (!ip || !cidr) return false;
  const a = normalized(ip);
  const c = normalized({ v: cidr.v, bytes: cidr.bytes });
  const bits = cidr.v === 6 && c.v === 4 ? cidr.bits - 96 : cidr.bits;
  if (a.v !== c.v || bits < 0) return false;
  return samePrefix(a.bytes, c.bytes, bits);
}

/** Do two address strings name the same address (a mapped IPv6 address equals the IPv4 one it wraps)? */
export function sameAddress(a, b) {
  const x = parseIp(a); const y = parseIp(b);
  if (!x || !y) return false;
  const nx = normalized(x); const ny = normalized(y);
  return nx.v === ny.v && samePrefix(nx.bytes, ny.bytes, nx.v === 4 ? 32 : 128);
}
