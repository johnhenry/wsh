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
export const KEY_OPTION_ERRORS = Object.freeze(['unknown-option', 'bad-syntax', 'bad-value', 'duplicate-option', 'unknown-capability', 'bad-capability']);

/**
 * The refusal codes of a request a key's options do not allow, stable across both hosts. `capability-missing` (#122, step two)
 * says which capability the request needed (`refusal.capability`); `key-expired` is a key past its `expires`.
 */
export const KEY_REQUEST_REFUSALS = Object.freeze([
  'pty-not-permitted', 'exec-not-permitted', 'file-transfer-not-permitted', 'forced-command', 'max-sessions',
  'mcp-not-permitted', 'relay-not-permitted', 'key-admin-not-permitted', 'capability-missing', 'key-expired',
]);

/** Options that only ask for less than wsh offers anyway: accepted, no effect (wsh has no agent, X11 or user rc to forward). */
const NO_OP_OPTIONS = new Set(['no-agent-forwarding', 'no-X11-forwarding', 'no-user-rc', 'no-port-forwarding']);
const FLAG_OPTIONS = new Set(['restrict', 'no-pty', 'permit-pty', 'permit-exec', 'permit-mcp', 'permit-file-transfer', 'permit-relay', ...NO_OP_OPTIONS]);
const VALUE_OPTIONS = new Set(['command', 'max-sessions', 'capabilities', 'expires']);
const NAME_RE = /^[A-Za-z][A-Za-z0-9_-]*$/;
const MAX_SESSIONS_RE = /^[1-9][0-9]{0,8}$/;

/**
 * What a key may do when it has no options at all. `capabilities` is `null` (no capability list: the options above decide
 * everything) or the list `capabilities="..."` gave (default-deny: only what it names); `expires` is `null` or the epoch second
 * from which the key is refused.
 */
export function fullAccess() {
  return { pty: true, exec: true, mcp: true, fileTransfer: true, relay: true, forcedCommand: null, maxSessions: null, capabilities: null, expires: null };
}

const fail = (code, reason) => ({ ok: false, code, reason });

// ── Capabilities (#122, step two) ────────────────────────────────────────────────────────────────────────────────────────
//
//   exec  pty  relay  fs:read  fs:write
//   gateway:tcp:<host>:<port>   gateway:udp:<host>:<port>   gateway:listen:tcp:<port>
//   unix:<path>   unix:listen:<path>   endpoint:<name>   mcp:<tool>   target:<name>   rpc:<protocol>
//
// `<host>` is a name, an IP literal (IPv6 in brackets), `*`, or `*.suffix` (any subdomain, not the apex); `<port>` a number or
// `*`; `<path>` absolute, exact or `/dir/*` (anything below `/dir`), no `.` or `..`; `<name>`, `<tool>` exact or `*`.

const NAME_CAP_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const TOOL_CAP_RE = /^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}$/;
const DOMAIN_RE = /^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$/;
const OBJECT_ROOT_RE = /^[A-Za-z_$][A-Za-z0-9_$-]{0,63}$/;
/** The operations of `wsh-objects` a capability can name (`objects:ROOT:OP`). */
const OBJECT_OPS = ['get', 'call', 'set'];
const SIMPLE_CAPS =new Set(['exec', 'pty', 'relay', 'fs:read', 'fs:write']);

const capFail = (code, reason) => ({ ok: false, code, reason });

function parsePort(s) {
  if (s === '*') return { port: '*' };
  if (!/^[1-9][0-9]{0,4}$/.test(s) || Number(s) > 65535) return null;
  return { port: Number(s) };
}

function parseHostPort(s) {
  let host; let port;
  if (s.startsWith('[')) {
    const close = s.indexOf(']');
    if (close < 0 || s[close + 1] !== ':') return null;
    host = s.slice(0, close + 1);
    port = s.slice(close + 2);
    if (!/^\[[0-9A-Fa-f:.]+\]$/.test(host)) return null;
  } else {
    const idx = s.lastIndexOf(':');
    if (idx < 0) return null;
    host = s.slice(0, idx);
    port = s.slice(idx + 1);
    const domain = host.startsWith('*.') ? host.slice(2) : host;
    if (host !== '*' && !DOMAIN_RE.test(domain)) return null;
  }
  const p = parsePort(port);
  return p ? { host: host.toLowerCase(), port: p.port } : null;
}

/** The segments of an absolute path with no empty, `.` or `..` segment, or null. */
function pathSegments(path) {
  if (typeof path !== 'string' || !path.startsWith('/')) return null;
  const segs = path.slice(1).split('/');
  return segs.every((s) => s !== '' && s !== '.' && s !== '..') ? segs : null;
}

function parsePathPattern(s) {
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u0020\u007f,"'\\]/.test(s)) return null;
  if (s === '/*') return { path: '/', prefix: true };
  if (s.endsWith('/*')) {
    const dir = s.slice(0, -2);
    return pathSegments(dir) && !dir.includes('*') ? { path: dir, prefix: true } : null;
  }
  return pathSegments(s) && !s.includes('*') ? { path: s, prefix: false } : null;
}

/** One capability, or a `{ ok: false }` with the stable code. */
function parseCapability(raw) {
  if (raw === '') return capFail('bad-capability', 'empty capability');
  if (/\s/.test(raw)) return capFail('bad-capability', `capability ${JSON.stringify(raw)} contains whitespace`);
  const bad = (why) => capFail('bad-capability', `capability ${JSON.stringify(raw)}: ${why}`);
  if (SIMPLE_CAPS.has(raw)) return { ok: true, cap: { raw, kind: raw } };
  if (raw.startsWith('gateway:')) {
    const rest = raw.slice('gateway:'.length);
    if (rest.startsWith('tcp:') || rest.startsWith('udp:')) {
      const hp = parseHostPort(rest.slice(4));
      return hp ? { ok: true, cap: { raw, kind: rest.slice(0, 3), host: hp.host, port: hp.port } } : bad('expected gateway:<tcp|udp>:<host>:<port>');
    }
    if (rest.startsWith('listen:tcp:')) {
      const p = parsePort(rest.slice('listen:tcp:'.length));
      return p ? { ok: true, cap: { raw, kind: 'listen-tcp', port: p.port } } : bad('expected gateway:listen:tcp:<port>');
    }
    return capFail('unknown-capability', `unknown capability ${JSON.stringify(raw)}`);
  }
  if (raw.startsWith('unix:')) {
    const listen = raw.startsWith('unix:listen:');
    const pat = parsePathPattern(raw.slice(listen ? 'unix:listen:'.length : 'unix:'.length));
    return pat ? { ok: true, cap: { raw, kind: listen ? 'listen-unix' : 'unix', ...pat } } : bad('expected an absolute path, exact or ending in /*, without . or ..');
  }
  const named = (prefix, kind, re, allowStar) => {
    const v = raw.slice(prefix.length);
    return (allowStar && v === '*') || re.test(v) ? { ok: true, cap: { raw, kind, name: v } } : bad(`expected ${prefix}<name>`);
  };
  if (raw.startsWith('endpoint:')) return named('endpoint:', 'endpoint', NAME_CAP_RE, true);
  if (raw.startsWith('target:')) return named('target:', 'target', NAME_CAP_RE, true);
  if (raw.startsWith('mcp:')) return named('mcp:', 'mcp', TOOL_CAP_RE, true);
  if (raw.startsWith('rpc:')) return named('rpc:', 'rpc', NAME_CAP_RE, false);
  if (raw.startsWith('objects:')) {
    // objects:ROOT or objects:ROOT:OP (#190): a root of `wsh-objects` (or `*`), and optionally one operation on it. JS hosts only.
    const parts = raw.slice('objects:'.length).split(':');
    const [root, op, ...rest] = parts;
    if (rest.length || !(root === '*' || OBJECT_ROOT_RE.test(root))) return bad('expected objects:<root>[:<get|call|set>]');
    if (op !== undefined && !OBJECT_OPS.includes(op)) return bad(`the operation must be one of ${OBJECT_OPS.join(', ')}`);
    return { ok: true, cap: { raw, kind: 'objects', name: root, op: op ?? null } };
  }
  return capFail('unknown-capability', `unknown capability ${JSON.stringify(raw)}`);
}

/**
 * Parse a capability list (`capabilities="exec,fs:read"`, or what an `authorize()` callback returns).
 * @param {string | string[]} list
 * @returns {{ ok: true, capabilities: string[], parsed: object[] } | { ok: false, code: string, reason: string }}
 */
export function parseCapabilityList(list) {
  const raws = Array.isArray(list) ? list : (list === '' ? [] : String(list).split(','));
  const parsed = [];
  for (const raw of raws) {
    if (typeof raw !== 'string') return capFail('bad-capability', 'capabilities must be strings');
    const r = parseCapability(raw);
    if (!r.ok) return r;
    parsed.push(r.cap);
  }
  return { ok: true, capabilities: raws.slice(), parsed };
}

const DAYS = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
const isLeap = (y) => (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
/** Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's `days_from_civil`). */
function daysFromCivil(y, m, d) {
  const yy = m <= 2 ? y - 1 : y;
  const era = Math.floor(yy / 400);
  const yoe = yy - era * 400;
  const doy = Math.floor((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1;
  return era * 146097 + yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy - 719468;
}

/**
 * An RFC 3339 timestamp (`2030-01-01T00:00:00Z`, `...+01:00`, fractional seconds allowed and dropped; `T` and `Z` upper case;
 * no leap second) as whole epoch seconds, or `null`. The Rust server parses the same way.
 * @param {string} s
 * @returns {number | null}
 */
export function parseRfc3339(s) {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|([+-])(\d{2}):(\d{2}))$/.exec(String(s));
  if (!m) return null;
  const [y, mo, d, h, mi, se] = [m[1], m[2], m[3], m[4], m[5], m[6]].map(Number);
  if (y < 1970 || mo < 1 || mo > 12 || d < 1 || d > (mo === 2 && isLeap(y) ? 29 : DAYS[mo - 1])) return null;
  if (h > 23 || mi > 59 || se > 59) return null;
  let offset = 0;
  if (m[7]) {
    const oh = Number(m[8]); const om = Number(m[9]);
    if (oh > 23 || om > 59) return null;
    offset = (m[7] === '+' ? 1 : -1) * (oh * 3600 + om * 60);
  }
  return daysFromCivil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se - offset;
}

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
  let caps = null;
  let expires = null;
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
    } else if (name === 'capabilities') {
      const r = parseCapabilityList(value);
      if (!r.ok) return r;
      caps = r;
    } else if (name === 'expires') {
      expires = parseRfc3339(value);
      if (expires === null) return fail('bad-value', 'expires must be an RFC 3339 timestamp such as 2030-01-01T00:00:00Z');
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
    capabilities: caps ? caps.capabilities : null,
    expires,
  };
  // The parsed form of the list, for the checks; not part of the permissions' value.
  Object.defineProperty(out, '_caps', { value: caps ? caps.parsed : null, enumerable: false });
  // A key tied to one command is not a shell, a file, an MCP or a relay key, whatever else the line says.
  if (command !== null) { out.pty = false; out.fileTransfer = false; out.mcp = false; out.relay = false; out.exec = true; }
  return { ok: true, permissions: out };
}

/** The parsed capability list of `p`, or null when the key has none. */
const capsOf = (p) => p._caps ?? (Array.isArray(p.capabilities) ? parseCapabilityList(p.capabilities).parsed : null);

const FS_READ_OPS = new Set(['stat', 'list', 'read']);

function hostMatches(patternHost, host) {
  const h = String(host).toLowerCase();
  const norm = h.includes(':') && !h.startsWith('[') ? `[${h}]` : h;
  if (patternHost === '*') return true;
  if (patternHost.startsWith('*.')) return norm.endsWith(patternHost.slice(1)) && norm.length > patternHost.length - 1;
  return norm === patternHost;
}
const portMatches = (patternPort, port) => patternPort === '*' || patternPort === port;
function pathMatches(cap, path) {
  const segs = pathSegments(path);
  if (!segs) return false;
  if (!cap.prefix) return path === cap.path;
  const dir = cap.path === '/' ? '' : cap.path;
  return path.startsWith(`${dir}/`) && path.length > dir.length + 1;
}
const nameMatches = (cap, name) => cap.name === '*' || cap.name === name;

/**
 * The capability part of a request check (the key has a capability list): `null` when the list covers `req`, else
 * `{ code: 'capability-missing', capability, reason }`.
 */
function capabilityRefusal(p, req) {
  const caps = capsOf(p);
  const has = (kind) => caps.some((c) => c.kind === kind);
  const need = (raw, ok) => (ok ? null : { code: 'capability-missing', capability: raw, reason: `missing capability ${raw}` });
  const target = () => (req.target === undefined || req.target === null ? null
    : need(`target:${req.target}`, caps.some((c) => c.kind === 'target' && nameMatches(c, req.target))));
  switch (req.kind) {
    case 'open': {
      let r;
      if (req.channel === 'pty') r = need('pty', has('pty'));
      else if (req.channel === 'exec') r = need('exec', has('exec'));
      else if (req.channel === 'file') { const need_ = req.direction === 'download' ? 'fs:read' : 'fs:write'; r = need(need_, has(need_)); }
      else if (req.channel === 'rpc') {
        const proto = req.protocol;
        // The file rpc has read and write methods on one channel: a key without both is refused it (a client falls back to
        // FileOp and the file channels, which are checked per operation).
        if (proto === 'wsh-fs') r = need('fs:read', has('fs:read')) ?? need('fs:write', has('fs:write'));
        // A handler that narrows by capability itself (`capabilityScoped`, req.scoped) may be opened by a key that names any
        // tool; every other `mcp` handler would show a `mcp:search` key all of its tools, so it still needs `mcp:*`.
        else if (proto === 'mcp') r = req.scoped ? need('mcp:<tool>', has('mcp')) : need('mcp:*', caps.some((c) => c.kind === 'mcp' && c.name === '*'));
        // Same for `wsh-objects`: a key that names roots (`objects:window:get`) may open it without `rpc:wsh-objects`, and is limited to them.
        else if (proto === 'wsh-objects' && req.scoped) r = need('rpc:wsh-objects', has('objects') || caps.some((c) => c.kind === 'rpc' && c.name === proto));
        else r = need(`rpc:${proto}`, caps.some((c) => c.kind === 'rpc' && c.name === proto));
      } else r = need(req.channel, false);
      return r ?? target();
    }
    case 'file-op': {
      const raw = FS_READ_OPS.has(req.op) ? 'fs:read' : 'fs:write';
      return need(raw, has(raw)) ?? target();
    }
    case 'mcp': return need('mcp:*', has('mcp'));
    case 'mcp-call': case 'mcp-tool': return need(`mcp:${req.tool}`, caps.some((c) => c.kind === 'mcp' && nameMatches(c, req.tool)));
    // An operation of `wsh-objects` on a root (`op`: get, call, set, or `walk`: reading on the way to something): a key that names no root
    // with `objects:` is limited by `rpc:wsh-objects` alone (all roots, as before); one that names roots is limited to them.
    case 'objects': {
      const named = caps.filter((c) => c.kind === 'objects');
      if (!named.length) return need('rpc:wsh-objects', caps.some((c) => c.kind === 'rpc' && c.name === 'wsh-objects'));
      return need(`objects:${req.root}${req.op === 'walk' ? '' : `:${req.op}`}`, named.some((c) => nameMatches(c, req.root) && (req.op === 'walk' || c.op === null || c.op === req.op)));
    }
    case 'relay': return need('relay', has('relay'));
    // Installing a key gives a key with no capability list, so a key with one never may.
    case 'key-admin': return { code: 'key-admin-not-permitted', reason: 'installing a key is not permitted for a restricted key' };
    case 'tcp': case 'udp': {
      const raw = `gateway:${req.kind}:${req.host}:${req.port}`;
      return need(raw, caps.some((c) => c.kind === req.kind && hostMatches(c.host, req.host) && portMatches(c.port, req.port)));
    }
    case 'dns': return need(`gateway:tcp:${req.name}:*`, caps.some((c) => c.kind === 'tcp' && hostMatches(c.host, req.name)));
    case 'listen-tcp': return need(`gateway:listen:tcp:${req.port}`, caps.some((c) => c.kind === 'listen-tcp' && portMatches(c.port, req.port)));
    case 'unix': return need(`unix:${req.path}`, caps.some((c) => c.kind === 'unix' && pathMatches(c, req.path)));
    case 'listen-unix': return need(`unix:listen:${req.path}`, caps.some((c) => c.kind === 'listen-unix' && pathMatches(c, req.path)));
    case 'endpoint': return need(`endpoint:${req.name}`, caps.some((c) => c.kind === 'endpoint' && nameMatches(c, req.name))) ?? target();
    case 'target': return need(`target:${req.name}`, caps.some((c) => c.kind === 'target' && nameMatches(c, req.name)));
    default: return need(String(req.kind), false);
  }
}

/**
 * Whether a key with `permissions` may make this request: `null` when allowed, else `{ code, reason }` (`code` is one of
 * `KEY_REQUEST_REFUSALS`; for `capability-missing` also `capability`, what the request needed). Checked in this order: expiry,
 * the options (`restrict`, `permit-*`, `command=`, `max-sessions=`), then the capability list when the key has one.
 *
 * Requests: `{ kind: 'login' }`; `{ kind: 'open', channel: 'pty' | 'exec' }`; `{ kind: 'open', channel: 'file', direction:
 * 'upload' | 'download' }`; `{ kind: 'open', channel: 'rpc', protocol }`; `{ kind: 'file-op', op }`; `{ kind: 'mcp' }`
 * (discovery), `{ kind: 'mcp-call' | 'mcp-tool', tool }`; `{ kind: 'relay' }`; `{ kind: 'key-admin' }`; the gateway:
 * `{ kind: 'tcp' | 'udp', host, port }`, `{ kind: 'dns', name }`, `{ kind: 'listen-tcp', port }`, `{ kind: 'unix' |
 * 'listen-unix', path }`, `{ kind: 'endpoint', name, target? }`; `{ kind: 'target', name }`. A request may carry `target` (open,
 * file-op, endpoint): the target it names. `activeSessions` is how many pty/exec sessions the key has open (for
 * `max-sessions`); `now` is the epoch second to test `expires` against (default: now).
 *
 * @param {ReturnType<typeof fullAccess>} p
 * @param {object} req
 * @param {{ activeSessions?: number, now?: number }} [state]
 * @returns {null | { code: string, reason: string, capability?: string }}
 */
export function checkKeyRequest(p, req, { activeSessions = 0, now } = {}) {
  if (p.expires !== null && p.expires !== undefined && (now ?? Math.floor(Date.now() / 1000)) >= p.expires) {
    return { code: 'key-expired', reason: 'this key has expired' };
  }
  if (req.kind === 'login') return null;
  const refused = optionsRefusal(p, req, activeSessions);
  if (refused) return refused;
  return capsOf(p) ? capabilityRefusal(p, req) : null;
}

/** The options part (`restrict`, `permit-*`, `command=`, `max-sessions=`) of a request check. */
function optionsRefusal(p, req, activeSessions) {
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
    case 'mcp': case 'mcp-call': case 'mcp-tool': return p.mcp ? null : no('mcp-not-permitted', 'MCP not permitted for this key');
    case 'relay': return p.relay ? null : no('relay-not-permitted', 'relay not permitted for this key');
    // The gateway, endpoints and targets are not scoped by the options (only by capabilities).
    case 'tcp': case 'udp': case 'dns': case 'listen-tcp': case 'unix': case 'listen-unix': case 'endpoint': case 'target': case 'objects': return null;
    // Installing another key (`AuthorizedKeyAdd`, which the Rust server serves): the new key has no options, so only a key that
    // is not restricted at all may add one -- a restricted key would otherwise mint an unrestricted one.
    case 'key-admin':
      return p.pty && p.exec && p.mcp && p.fileTransfer && p.relay && p.forcedCommand === null ? null
        : no('key-admin-not-permitted', 'installing a key is not permitted for a restricted key');
    default: return no('exec-not-permitted', `unknown request ${JSON.stringify(req.kind)}`);
  }
}

/**
 * What an `authorize()` callback may return instead of `true`: `{ capabilities: string | string[], expires?: string | Date | number }`.
 * The same grammar as `capabilities="..."` (a string is comma-separated); `expires` an RFC 3339 string, a `Date` or epoch
 * milliseconds. The result is a permission set that narrows the key's own options (it never widens them).
 *
 * @param {{ capabilities?: string | string[], expires?: string | Date | number }} grant
 * @returns {{ ok: true, permissions: ReturnType<typeof fullAccess> } | { ok: false, code: string, reason: string }}
 */
export function grantPermissions(grant) {
  const out = fullAccess();
  let parsed = null;
  if (grant.capabilities !== undefined) {
    const r = parseCapabilityList(grant.capabilities);
    if (!r.ok) return r;
    out.capabilities = r.capabilities;
    parsed = r.parsed;
  }
  if (grant.expires !== undefined) {
    let secs = null;
    if (typeof grant.expires === 'string') secs = parseRfc3339(grant.expires);
    else if (grant.expires instanceof Date && Number.isFinite(grant.expires.getTime())) secs = Math.floor(grant.expires.getTime() / 1000);
    else if (typeof grant.expires === 'number' && Number.isFinite(grant.expires)) secs = Math.floor(grant.expires / 1000);
    if (secs === null) return fail('bad-value', 'expires must be an RFC 3339 string, a Date or epoch milliseconds');
    out.expires = secs;
  }
  Object.defineProperty(out, '_caps', { value: parsed, enumerable: false });
  return { ok: true, permissions: out };
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
