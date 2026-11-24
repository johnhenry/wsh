/**
 * Which login names a host admits. The default is the shape of an OS account name (a letter or `_`, then letters,
 * digits, `_`, `.`, `-`, up to 64 characters), because a name reaches `exec` environments, file paths and logs of hosts
 * that really do map it to an account. A host that does not (a page, a mesh peer whose name is a base64url identity
 * hash that may start with a digit or `-`) can say what it admits with `usernamePattern`.
 *
 * What a pattern cannot loosen: the name is a string of 1 to 256 characters with no control character (C0, DEL, C1,
 * line or paragraph separators), no slash and no backslash, and is not `.` or `..`. The pattern narrows further; it does not get to admit those.
 *
 * Pure JavaScript, browser-safe (the memory host imports it).
 */

export const DEFAULT_USERNAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;

const MAX_USERNAME_LENGTH = 256;

/** A control character (C0, DEL, C1), a line or paragraph separator (code points 0x2028, 0x2029), `/` (0x2f) or `\` (0x5c). */
function forbiddenCode(c) {
  return c <= 0x1f || (c >= 0x7f && c <= 0x9f) || c === 0x2028 || c === 0x2029 || c === 0x2f || c === 0x5c;
}

function hasForbidden(s) {
  for (let i = 0; i < s.length; i++) if (forbiddenCode(s.charCodeAt(i))) return true;
  return false;
}

/**
 * Validate a `usernamePattern` option and return the RegExp to test names with (never global or sticky, so `test()`
 * keeps no state between logins).
 * @param {RegExp | string | undefined | null} value
 * @param {string} label  `createWshServer` etc., for the error message
 * @returns {RegExp}
 */
export function resolveUsernamePattern(value, label) {
  if (value === undefined || value === null) return DEFAULT_USERNAME_PATTERN;
  let re;
  try {
    if (value instanceof RegExp) re = new RegExp(value.source, value.flags.replace(/[gy]/g, ''));
    else if (typeof value === 'string') re = new RegExp(value);
  } catch (e) {
    throw new TypeError(`${label}: usernamePattern is not a valid pattern (${e.message})`);
  }
  if (!re) throw new TypeError(`${label}: usernamePattern must be a RegExp or a pattern string`);
  if (re.test('')) throw new TypeError(`${label}: usernamePattern must not match the empty name`);
  return re;
}

/**
 * May this login name be admitted under `pattern`?
 * @param {RegExp} pattern  from `resolveUsernamePattern`
 * @param {unknown} name
 */
export function usernameAllowed(pattern, name) {
  if (typeof name !== 'string' || name.length === 0 || name.length > MAX_USERNAME_LENGTH || hasForbidden(name)) return false;
  if (name === '.' || name === '..') return false; // a path component, whatever the pattern says
  return pattern.test(name);
}
