/**
 * `authorized_keys` options (wsh #122): what a key's leading options mean, parsed the same way by the Node host (this file) and
 * the Rust `wsh-server` (`crates/wsh-server/src/auth/permissions.rs`). `spec/key-options.vectors.json` holds the shared test
 * vectors both suites run, so the two cannot drift. Browser-safe (no Node imports): the in-memory host uses it too.
 *
 * A line is `[options] ssh-ed25519 <base64> [comment]`. `options` is one token (no whitespace outside double quotes) of
 * comma-separated items, each `name` or `name=value`, where a value is `"..."` (a `\"` is a quote, any other backslash is
 * literal) or a bare token. Anything this file does not understand REFUSES the key: it is not on the allowlist at all, with a
 * reason. Nothing is ever skipped silently and then granted.
 */

import { parseSSHPublicKey, extractRawFromSSHWire } from './auth.mjs';

/** The refusal codes of a key line, stable across both hosts. */
export const KEY_OPTION_ERRORS = Object.freeze(['unknown-option', 'bad-syntax', 'bad-value', 'duplicate-option']);

/** The refusal codes of a request a key's options do not allow, stable across both hosts. */
export const KEY_REQUEST_REFUSALS = Object.freeze([
  'pty-not-permitted', 'exec-not-permitted', 'file-transfer-not-permitted', 'forced-command', 'max-sessions',
  'mcp-not-permitted', 'relay-not-permitted', 'key-admin-not-permitted',
]);

/** Options that only ask for less than wsh offers anyway: accepted, no effect (wsh has no agent, X11 or user rc to forward). */
const NO_OP_OPTIONS = new Set(['no-agent-forwarding', 'no-X11-forwarding', 'no-user-rc', 'no-port-forwarding']);
const FLAG_OPTIONS = new Set(['restrict', 'no-pty', 'permit-pty', 'permit-exec', 'permit-mcp', 'permit-file-transfer', 'permit-relay', ...NO_OP_OPTIONS]);
const VALUE_OPTIONS = new Set(['command', 'max-sessions']);
const NAME_RE = /^[A-Za-z][A-Za-z0-9_-]*$/;
const MAX_SESSIONS_RE = /^[1-9][0-9]{0,8}$/;

/** What a key may do when it has no options at all. */
export function fullAccess() {
  return { pty: true, exec: true, mcp: true, fileTransfer: true, relay: true, forcedCommand: null, maxSessions: null };
}

const fail = (code, reason) => ({ ok: false, code, reason });

/**
 * Split the options token into `[name, value | null]` items, or fail.
 * @returns {{ ok: true, items: Array<[string, string | null]> } | { ok: false, code: string, reason: string }}
 */
function tokenize(text) {
  const items = [];
  let i = 0;
  const n = text.length;
  for (;;) {
    let name = '';
    while (i < n && text[i] !== ',' && text[i] !== '=') {
      const ch = text[i];
      if (ch === '"' || ch === "'" || ch === ' ' || ch === '\t') return fail('bad-syntax', `unexpected ${JSON.stringify(ch)} in an option name`);
      name += ch; i++;
    }
    if (!name) return fail('bad-syntax', 'empty option (a stray comma)');
    let value = null;
    if (text[i] === '=') {
      i++;
      if (text[i] === '"') {
        i++;
        let v = '';
        let closed = false;
        while (i < n) {
          const ch = text[i];
          if (ch === '\\' && text[i + 1] === '"') { v += '"'; i += 2; continue; }
          if (ch === '"') { closed = true; i++; break; }
          v += ch; i++;
        }
        if (!closed) return fail('bad-syntax', `unterminated quote in ${name}=`);
        if (i < n && text[i] !== ',') return fail('bad-syntax', `text after the closing quote of ${name}=`);
        value = v;
      } else {
        let v = '';
        while (i < n && text[i] !== ',') {
          const ch = text[i];
          if (ch === '"' || ch === "'" || ch === '=' || ch === ' ' || ch === '\t') return fail('bad-syntax', `unexpected ${JSON.stringify(ch)} in the value of ${name}= (quote the value with double quotes)`);
          v += ch; i++;
        }
        value = v;
      }
    }
    items.push([name, value]);
    if (i >= n) return { ok: true, items };
    i++; // the comma
    if (i >= n) return fail('bad-syntax', 'empty option (a trailing comma)');
  }
}

/**
 * Parse an options string into effective permissions. `null`/`undefined`/`''` mean "no options": full access.
 * @param {string | null | undefined} text
 * @returns {{ ok: true, permissions: ReturnType<typeof fullAccess> } | { ok: false, code: string, reason: string }}
 */
export function parseKeyOptions(text) {
  if (text === null || text === undefined || text === '') return { ok: true, permissions: fullAccess() };
  const tok = tokenize(String(text));
  if (!tok.ok) return tok;
  const seen = new Set();
  const flags = new Set();
  let command = null;
  let maxSessions = null;
  for (const [name, value] of tok.items) {
    if (!NAME_RE.test(name) || !(FLAG_OPTIONS.has(name) || VALUE_OPTIONS.has(name))) return fail('unknown-option', `unknown option ${JSON.stringify(name)}`);
    if (seen.has(name)) return fail('duplicate-option', `option ${name} given twice`);
    seen.add(name);
    if (FLAG_OPTIONS.has(name)) {
      if (value !== null) return fail('bad-value', `option ${name} takes no value`);
      flags.add(name);
    } else if (value === null) {
      return fail('bad-value', `option ${name} needs a value`);
    } else if (name === 'command') {
      // eslint-disable-next-line no-control-regex
      if (!value || /[\u0000-\u001f\u007f]/.test(value)) return fail('bad-value', 'command must be a non-empty string without control characters');
      command = value;
    } else {
      if (!MAX_SESSIONS_RE.test(value)) return fail('bad-value', 'max-sessions must be a positive whole number');
      maxSessions = Number(value);
    }
  }
  const restricted = flags.has('restrict');
  const grant = (permit) => (restricted ? flags.has(permit) : true);
  const shell = grant('permit-pty');
  const out = {
    pty: shell && !flags.has('no-pty'),
    exec: restricted ? (flags.has('permit-exec') || flags.has('permit-pty') || command !== null) : true,
    mcp: grant('permit-mcp'),
    fileTransfer: grant('permit-file-transfer'),
    relay: grant('permit-relay'),
    forcedCommand: command,
    maxSessions,
  };
  // A key tied to one command is not a shell, a file, an MCP or a relay key, whatever else the line says.
  if (command !== null) { out.pty = false; out.fileTransfer = false; out.mcp = false; out.relay = false; out.exec = true; }
  return { ok: true, permissions: out };
}

/**
 * Whether a key with `permissions` may make this request. `null` when allowed, else `{ code, reason }` (`code` is one of
 * `KEY_REQUEST_REFUSALS`). Requests: `{ kind: 'open', channel: 'pty' | 'exec' | 'file' }`, `{ kind: 'open', channel: 'rpc',
 * protocol }`, `{ kind: 'file-op' }`, `{ kind: 'mcp' }`, `{ kind: 'relay' }`; `activeSessions` is how many pty/exec sessions
 * the key has open (for `max-sessions`).
 *
 * @param {ReturnType<typeof fullAccess>} p
 * @param {{ kind: string, channel?: string, protocol?: string }} req
 * @param {{ activeSessions?: number }} [state]
 * @returns {null | { code: string, reason: string }}
 */
export function checkKeyRequest(p, req, { activeSessions = 0 } = {}) {
  const no = (code, reason) => ({ code, reason });
  switch (req.kind) {
    case 'open': {
      const ch = req.channel;
      if (p.forcedCommand !== null && ch !== 'exec') return no('forced-command', 'key is restricted to forced exec command');
      if (ch === 'pty' && !p.pty) return no('pty-not-permitted', 'PTY not permitted for this key');
      if (ch === 'exec' && !p.exec) return no('exec-not-permitted', 'exec access not permitted for this key');
      if (ch === 'file' && !p.fileTransfer) return no('file-transfer-not-permitted', 'file transfer not permitted for this key');
      if (ch === 'rpc') {
        // wsh-fs is the file channel, mcp is the MCP bridge, wsh-host only says what the host is; any other protocol is the
        // embedder's own and is open to a key that is not restricted at all.
        const proto = req.protocol;
        if (proto === 'wsh-fs' && !p.fileTransfer) return no('file-transfer-not-permitted', 'file transfer not permitted for this key');
        if (proto === 'mcp' && !p.mcp) return no('mcp-not-permitted', 'MCP not permitted for this key');
        if (proto !== 'wsh-fs' && proto !== 'mcp' && proto !== 'wsh-host' && !(p.pty && p.exec && p.mcp && p.fileTransfer && p.relay)) {
          return no('exec-not-permitted', 'this protocol is not permitted for a restricted key');
        }
      }
      if ((ch === 'pty' || ch === 'exec') && p.maxSessions !== null && activeSessions >= p.maxSessions) {
        return no('max-sessions', `max sessions for this key reached (${p.maxSessions})`);
      }
      return null;
    }
    case 'file-op':
      if (p.forcedCommand !== null) return no('forced-command', 'key is restricted to forced exec command');
      return p.fileTransfer ? null : no('file-transfer-not-permitted', 'file transfer not permitted for this key');
    case 'mcp': return p.mcp ? null : no('mcp-not-permitted', 'MCP not permitted for this key');
    case 'relay': return p.relay ? null : no('relay-not-permitted', 'relay not permitted for this key');
    // Installing another key (`AuthorizedKeyAdd`, which the Rust server serves): the new key has no options, so only a key that
    // is not restricted at all may add one -- a restricted key would otherwise mint an unrestricted one.
    case 'key-admin':
      return p.pty && p.exec && p.mcp && p.fileTransfer && p.relay && p.forcedCommand === null ? null
        : no('key-admin-not-permitted', 'installing a key is not permitted for a restricted key');
    default: return no('exec-not-permitted', `unknown request ${JSON.stringify(req.kind)}`);
  }
}

const isSpace = (c) => c === ' ' || c === '\t';

/**
 * Parse one `authorized_keys` line.
 *  - `{ skip: reason }` -- nothing to act on: blank, a comment, a key type this host does not serve (only `ssh-ed25519` is
 *    used), or a line that cannot be split into options and a key (an unterminated quote);
 *  - `{ refused: { code, reason }, key }` -- an ed25519 key whose options are not understood: it must not be let in;
 *  - `{ key, options, permissions }` -- a usable entry (`options` is the raw options token or `null`).
 *
 * @param {string} raw
 */
export function parseAuthorizedKeyLine(raw) {
  const line = String(raw).trim();
  if (!line || line.startsWith('#')) return { skip: 'blank or comment' };
  let rest = line;
  let options = null;
  if (!/^ssh-ed25519[ \t]/.test(line)) {
    // Options end at the first whitespace outside double quotes.
    let inQuote = false;
    let i = 0;
    for (; i < line.length; i++) {
      const c = line[i];
      if (inQuote) {
        if (c === '\\' && line[i + 1] === '"') { i++; continue; }
        if (c === '"') inQuote = false;
      } else if (c === '"') inQuote = true;
      else if (isSpace(c)) break;
    }
    if (inQuote) return { skip: 'unterminated quote in the options' };
    options = line.slice(0, i);
    rest = line.slice(i).trim();
    if (!/^ssh-ed25519[ \t]/.test(rest)) return { skip: 'not an ssh-ed25519 key' };
  }
  let key;
  try {
    const parsed = parseSSHPublicKey(rest);
    key = extractRawFromSSHWire(parsed.data);
    if (!(key instanceof Uint8Array) || key.byteLength !== 32) return { skip: 'malformed key' };
  } catch { return { skip: 'malformed key' }; }
  const parsed = parseKeyOptions(options);
  if (!parsed.ok) return { refused: { code: parsed.code, reason: parsed.reason }, key, options };
  return { key, options, permissions: parsed.permissions };
}
