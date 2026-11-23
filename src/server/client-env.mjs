/**
 * Which environment variables a client may set for the command or shell a host runs (`Open.env`).
 *
 * The default is an allow-list in the spirit of sshd's `AcceptEnv`: `TERM`, `COLORTERM`, `LANG`, `LANGUAGE` and
 * `LC_*`. Anything else -- `PATH`, `LD_PRELOAD`, `BASH_ENV`, `NODE_OPTIONS` -- lets a client change what a host that
 * restricts what runs (an `exec` function, a fixed command set, a restricted shell) actually executes, so it takes
 * an explicit opt-in.
 *
 * Accepted forms of the option (`exec.clientEnv`, `pty.clientEnv`):
 *   undefined      the default allow-list above
 *   true           accept everything (the behaviour before this list existed)
 *   false          accept nothing
 *   string[]       exact names, or a prefix ending in `*` (`'LC_*'`); NOT merged with the default list
 *   (name, value) => boolean   decide per variable
 */

const NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
export const MAX_ENV_VARS = 64;
export const MAX_ENV_VALUE_BYTES = 4096;

/** The names a host accepts when `clientEnv` is not set. */
export const DEFAULT_CLIENT_ENV = Object.freeze(['TERM', 'COLORTERM', 'LANG', 'LANGUAGE', 'LC_*']);

const matcher = (patterns) => {
  const exact = new Set();
  const prefixes = [];
  for (const p of patterns) {
    if (typeof p !== 'string' || !p) throw new TypeError('clientEnv: list entries must be non-empty strings');
    if (p.endsWith('*')) prefixes.push(p.slice(0, -1)); else exact.add(p);
  }
  return (name) => exact.has(name) || prefixes.some((pre) => name.startsWith(pre));
};

/**
 * @param {undefined | boolean | string[] | ((name: string, value: string) => boolean)} option
 * @returns {(requested: unknown) => Record<string, string>} keeps only what the host accepts
 */
export function clientEnvFilter(option) {
  let allow;
  if (option === undefined) allow = matcher(DEFAULT_CLIENT_ENV);
  else if (option === true) allow = () => true;
  else if (option === false) allow = () => false;
  else if (Array.isArray(option)) allow = matcher(option);
  else if (typeof option === 'function') allow = option;
  else throw new TypeError('clientEnv must be true, false, an array of names or a function (name, value) => boolean');

  return (requested) => {
    const out = {};
    if (!requested || typeof requested !== 'object' || Array.isArray(requested)) return out;
    let seen = 0;
    for (const [name, value] of Object.entries(requested)) {
      if (++seen > MAX_ENV_VARS) break;
      if (!NAME_RE.test(name) || typeof value !== 'string' || value.length > MAX_ENV_VALUE_BYTES || value.includes('\0')) continue;
      let ok = false;
      try { ok = allow(name, value) === true; } catch { ok = false; }
      if (ok) out[name] = value;
    }
    return out;
  };
}
