/**
 * The two pure helpers a page needs to reach a pipe relay (`@johnhenry/wsh/pipe-relay`): a fresh rendezvous id and the URL one side dials.
 * They are the relay module's own, kept here so that a page's bundle does not have to include the relay (which can listen, and so reaches
 * for `node:http`); `test/page-host.test.mjs` checks the two agree.
 */

const ID_RE = /^[A-Za-z0-9_-]{22,128}$/;
const ROLES = new Set(['host', 'operator']);
const MIN_ID_LENGTH = 22; // 16 random bytes, base64url
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/**
 * A fresh rendezvous id: 128 bits from the CSPRNG you pass (`window.crypto`), base64url (22 characters).
 * @param {{ getRandomValues(bytes: Uint8Array): Uint8Array }} cryptoImpl
 */
export function newRendezvousId(cryptoImpl) {
  if (typeof cryptoImpl?.getRandomValues !== 'function') throw new TypeError('newRendezvousId: needs a crypto with getRandomValues (the window\'s); or give the relay an id of your own');
  const bytes = cryptoImpl.getRandomValues(new Uint8Array(16));
  let out = '';
  let acc = 0;
  let bits = 0;
  for (const b of bytes) {
    acc = (acc << 8) | b; bits += 8;
    while (bits >= 6) { bits -= 6; out += ALPHABET[(acc >> bits) & 63]; }
  }
  if (bits > 0) out += ALPHABET[(acc << (6 - bits)) & 63];
  return out;
}

/**
 * The URL one side dials: `<relay>/r/<id>`, with `?role=host` for the host (the operator is the default).
 * @param {string} relayUrl
 * @param {string} id
 * @param {'host' | 'operator'} [role='operator']
 */
export function pipeUrl(relayUrl, id, role = 'operator') {
  if (!ID_RE.test(id)) throw new TypeError(`pipeUrl: the rendezvous id must be ${MIN_ID_LENGTH}-128 base64url characters`);
  if (!ROLES.has(role)) throw new TypeError("pipeUrl: role must be 'host' or 'operator'");
  const u = new URL(relayUrl);
  u.pathname = `${u.pathname.replace(/\/+$/, '')}/r/${id}`;
  u.search = role === 'host' ? '?role=host' : '';
  return u.toString();
}
