/**
 * A short-lived self-signed certificate for WebTransport's
 * `serverCertificateHashes` pinning, with no dependency: the X.509 structure
 * is small enough to assemble as DER by hand, and `node:crypto` signs it.
 *
 * The web platform's rules for a pinned certificate (what a browser enforces):
 * an ECDSA P-256 key, a validity period of at most 14 days, and the page pins
 * the SHA-256 of the DER certificate. Nothing else about it is checked (no
 * chain, and the name is not matched), but the subject alternative names are
 * filled in anyway so the same certificate also works for a client that does.
 */

import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import net from 'node:net';

/** What a browser allows for `serverCertificateHashes`. */
export const MAX_PINNED_CERT_DAYS = 14;
const DAY_MS = 24 * 60 * 60 * 1000;

const OID = {
  ecdsaWithSha256: '2a8648ce3d040302',
  commonName: '550403',
  subjectAltName: '551d11',
  extKeyUsage: '551d25',
  serverAuth: '2b06010505070301',
  keyUsage: '551d0f',
};

// ── DER ──────────────────────────────────────────────────────────────

const concat = (...parts) => Buffer.concat(parts.map((p) => (Buffer.isBuffer(p) ? p : Buffer.from(p))));
function der(tag, ...content) {
  const body = concat(...content);
  const n = body.length;
  const len = n < 0x80 ? Buffer.from([n]) : n < 0x100 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 0xff]);
  return concat(Buffer.from([tag]), len, body);
}
const seq = (...c) => der(0x30, ...c);
const set = (...c) => der(0x31, ...c);
const oid = (hex) => der(0x06, Buffer.from(hex, 'hex'));
const utf8 = (s) => der(0x0c, Buffer.from(s, 'utf8'));
const octets = (b) => der(0x04, b);
const bitString = (b) => der(0x03, Buffer.from([0]), b);
/** Positive INTEGER from big-endian bytes. */
function integer(bytes) {
  let b = Buffer.from(bytes);
  while (b.length > 1 && b[0] === 0) b = b.subarray(1);
  if (b[0] & 0x80) b = concat(Buffer.from([0]), b);
  return der(0x02, b);
}
function utcTime(date) {
  const p = (n) => String(n).padStart(2, '0');
  return der(0x17, Buffer.from(`${p(date.getUTCFullYear() % 100)}${p(date.getUTCMonth() + 1)}${p(date.getUTCDate())}${p(date.getUTCHours())}${p(date.getUTCMinutes())}${p(date.getUTCSeconds())}Z`, 'ascii'));
}

function ipBytes(addr) {
  if (net.isIPv4(addr)) return Buffer.from(addr.split('.').map(Number));
  // IPv6, possibly with "::" compression
  const [head, tail = ''] = addr.split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const groups = [...h, ...Array(8 - h.length - t.length).fill('0'), ...t];
  return Buffer.from(groups.flatMap((g) => { const v = parseInt(g || '0', 16); return [v >> 8, v & 0xff]; }));
}

function pem(label, derBytes) {
  const b64 = derBytes.toString('base64').match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----\n`;
}

/**
 * @param {object} [opts]
 * @param {string[]} [opts.hosts=['localhost', '127.0.0.1', '::1']] - DNS names and IP addresses for the SAN.
 * @param {number} [opts.validityDays=13] - At most 14 (a browser refuses a pinned certificate valid for longer).
 * @param {Date} [opts.now]
 * @returns {{ cert: string, privKey: string, hash: Uint8Array, hashHex: string, notBefore: Date, notAfter: Date }}
 *   `cert` / `privKey` are PEM; `hash` is the SHA-256 of the DER certificate, the value to pin.
 */
export function generateSelfSignedCertificate({ hosts = ['localhost', '127.0.0.1', '::1'], validityDays = 13, now = new Date() } = {}) {
  if (!(validityDays > 0) || validityDays > MAX_PINNED_CERT_DAYS) {
    throw new RangeError(`selfSigned: validityDays must be in (0, ${MAX_PINNED_CERT_DAYS}] -- browsers refuse a pinned certificate valid for longer`);
  }
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  // An hour of back-dating tolerates clock skew; the whole window stays under 14 days for validityDays <= 13.
  const skewMs = Math.min(60 * 60 * 1000, (MAX_PINNED_CERT_DAYS - validityDays) * DAY_MS);
  const notBefore = new Date(Math.floor((now.getTime() - skewMs) / 1000) * 1000);
  const notAfter = new Date(Math.floor((now.getTime() + validityDays * DAY_MS - skewMs) / 1000) * 1000);

  const name = seq(set(seq(oid(OID.commonName), utf8('wsh self-signed'))));
  const san = seq(...hosts.map((h) => (net.isIP(h) ? der(0x87, ipBytes(h)) : der(0x82, Buffer.from(h, 'ascii')))));
  const extensions = der(0xa3, seq(
    seq(oid(OID.keyUsage), der(0x01, Buffer.from([0xff])), octets(bitString(Buffer.from([0x80])))), // digitalSignature
    seq(oid(OID.extKeyUsage), octets(seq(oid(OID.serverAuth)))),
    seq(oid(OID.subjectAltName), octets(san)),
  ));
  const serial = randomBytes(16);
  serial[0] &= 0x7f;
  serial[0] |= 0x01;

  const tbs = seq(
    der(0xa0, integer([2])),                              // v3
    integer(serial),
    seq(oid(OID.ecdsaWithSha256)),
    name,
    seq(utcTime(notBefore), utcTime(notAfter)),
    name,
    publicKey.export({ type: 'spki', format: 'der' }),
    extensions,
  );
  const signature = sign('sha256', tbs, privateKey);       // DER-encoded ECDSA-Sig-Value
  const certDer = seq(tbs, seq(oid(OID.ecdsaWithSha256)), bitString(signature));
  const hash = new Uint8Array(createHash('sha256').update(certDer).digest());
  return {
    cert: pem('CERTIFICATE', certDer),
    privKey: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    hash,
    hashHex: Buffer.from(hash).toString('hex'),
    notBefore,
    notAfter,
  };
}
