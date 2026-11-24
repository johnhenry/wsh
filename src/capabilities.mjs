/**
 * `@johnhenry/wsh/capabilities` -- the notation of key capabilities, as a pure function (browser-safe, no Node import).
 *
 *   import { permits } from '@johnhenry/wsh/capabilities';
 *   permits(['exec', 'gateway:tcp:*.example.com:443', 'objects:window:get'], { kind: 'tcp', host: 'api.example.com', port: 443 }); // true
 *
 * What a list means (the grammar, what each wildcard matches, the request kinds and what each needs, and what an
 * implementation does with something it does not understand) is written in `spec/capabilities.md`, and
 * `spec/capabilities.vectors.json` holds the vectors that the JS evaluation and the Rust `wsh-server` both run. Both files are
 * published in the package (`@johnhenry/wsh/spec/capabilities.md`, `@johnhenry/wsh/spec/capabilities.vectors.json`), so another
 * implementation can run the same vectors.
 *
 * This is the same evaluation `@johnhenry/wsh/server`, the memory host and the page host run for a key's `capabilities="..."`;
 * it is exported so a registry of grants in another system (a mesh peer's) can use it instead of keeping a second reading
 * of the notation.
 */

import { grantPermissions, checkKeyRequest, parseCapabilityList } from './key-options.mjs';

/** The revision of the notation these functions implement: the `version` of `spec/capabilities.vectors.json`. */
export const CAPABILITIES_NOTATION_VERSION = 1;

export { parseCapabilityList };

/** `Date | epoch milliseconds | RFC 3339 string | undefined` as epoch seconds, or `undefined`. */
function toSeconds(now) {
  if (now === undefined || now === null) return undefined;
  const ms = now instanceof Date ? now.getTime() : now;
  if (typeof ms !== 'number' || !Number.isFinite(ms)) throw new TypeError('now must be a Date or epoch milliseconds');
  return Math.floor(ms / 1000);
}

/**
 * Whether a holder of `capabilities` may make `request`, with the reason when not: `null` when permitted, else `{ code, reason,
 * capability? }`. `code` is `capability-missing` (`capability` names what was needed) or `key-expired`; a list that has an entry
 * this implementation does not understand is refused whole, with its `unknown-capability` or `bad-capability` code (the list
 * permits nothing). `capabilities` that is not an array of strings (including `null` and `undefined`: no list is no grant) is refused
 * as `bad-capability`.
 *
 * @param {string[] | string} capabilities a list of capability strings (a comma separated string is read the same way as `capabilities="..."`)
 * @param {{ kind: string, [field: string]: unknown }} request what is asked; the kinds are in `spec/capabilities.md`
 * @param {{ expires?: string | Date | number, now?: Date | number }} [options] `expires`: an RFC 3339 string, a `Date` or epoch
 *   milliseconds, the instant from which the list is refused; `now`: a `Date` or epoch milliseconds (default: the present)
 * @returns {null | { code: string, reason: string, capability?: string }}
 */
export function checkCapabilities(capabilities, request, { expires, now } = {}) {
  if (!(Array.isArray(capabilities) || typeof capabilities === 'string')) {
    return { code: 'bad-capability', reason: 'a capability list is an array of strings' };
  }
  if (request === null || typeof request !== 'object' || typeof request.kind !== 'string') {
    return { code: 'capability-missing', reason: 'a request is an object with a kind' };
  }
  const granted = grantPermissions({ capabilities, ...(expires !== undefined ? { expires } : {}) });
  if (!granted.ok) return { code: granted.code, reason: granted.reason };
  return checkKeyRequest(granted.permissions, request, { now: toSeconds(now) });
}

/**
 * Whether a holder of `capabilities` may make `request`. Fails closed: a list with an entry this implementation does not
 * understand, a missing list, or a request of a kind it does not know permits nothing. See `checkCapabilities` for the reason.
 *
 * @param {string[] | string} capabilities
 * @param {{ kind: string, [field: string]: unknown }} request
 * @param {{ expires?: string | Date | number, now?: Date | number }} [options]
 * @returns {boolean}
 */
export function permits(capabilities, request, options) {
  return checkCapabilities(capabilities, request, options) === null;
}
