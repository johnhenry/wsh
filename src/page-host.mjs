/**
 * `@johnhenry/wsh/page` -- a web page (or any window-shaped realm) as a wsh host behind a pipe relay it chose (#190).
 *
 * ```js
 * import { captureWebMcp, createPageHost } from '@johnhenry/wsh/page';
 * captureWebMcp(window);                       // first, before the application registers its tools
 * // ... the application calls document.modelContext.registerTool({ name, description, inputSchema, execute }) ...
 * const host = await createPageHost({
 *   window,                                    // the only realm this touches; passing it exposes nothing by itself
 *   relay: 'wss://relay.example/pipe',         // a page cannot listen: it dials a relay, and prints host.operatorUrl for the operator
 *   name: 'shop-tab',
 *   authorizedKeys: [operatorPublicKeyLine],   // required: key login only, no password, no anonymous mode
 *   mcp: { allow: ['search_products', 'add_to_cart'], approve: 'consequential' },
 * });
 * ```
 *
 * What a remote session can do is exactly: open the `mcp` rpc channel and list and call the tools named in `mcp.allow` (narrowed
 * further by the key's `capabilities="mcp:TOOL"`), and, if `expose` is written, open the `wsh-objects` channel and read, call and set the
 * paths its allow-lists name on the roots it names (`rpc:wsh-objects` is the capability for that channel). Nothing is exposed by default,
 * and passing `window` is not exposing it. There is no exec, no file access, no gateway. The session must be SEALED (the pipe
 * relay then sees ciphertext only), a visible indicator with a Stop control is in the page while anyone is connected, and a
 * consequential tool waits for the person at the page to allow it. What this cannot make safe is in the README's Security model.
 *
 * Browser-safe, and it reads nothing but the `window` it is given: no `globalThis`, no `document`, no `navigator`
 * (`test/page-host.test.mjs` greps this file for them).
 */

import { createMemoryHost } from './memory-host.mjs';
import { resolveHostKey } from './host-backends.mjs';
import { generateKeyPair } from './auth.mjs';
import { pipeUrl } from './pipe-relay.mjs';
import { webmcpTools, captureWebMcp, createDomPrompt, timersOf, WEBMCP_DEFAULT_LIMITS } from './webmcp.mjs';
import { exposeObjects } from './objects.mjs';
import { OBJECTS_PROTOCOL } from './objects-core.mjs';
import { serveMcpOverDuplex } from './mcp-duplex.mjs';

export { webmcpTools, captureWebMcp, createDomPrompt, WEBMCP_DEFAULT_LIMITS, exposeObjects, serveMcpOverDuplex };
export { createDomIndicator as createPageIndicator };

const RECONNECT_START_MS = 1000;
const RECONNECT_MAX_MS = 30_000;
const WATCH_MS = 1000;

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

const BASE64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
/** A rendezvous id as the pipe relay wants it (16 random bytes, base64url: 22 characters), from the window's own CSPRNG rather than a global. */
function randomRendezvousId(cryptoImpl) {
  if (typeof cryptoImpl?.getRandomValues !== 'function') throw new TypeError('createPageHost: this window has no crypto.getRandomValues for a rendezvous id: give relay: { url, id }');
  let out = '';
  let acc = 0;
  let bits = 0;
  for (const b of cryptoImpl.getRandomValues(new Uint8Array(16))) {
    acc = (acc << 8) | b; bits += 8;
    while (bits >= 6) { bits -= 6; out += BASE64URL[(acc >> bits) & 63]; }
  }
  if (bits > 0) out += BASE64URL[(acc << (6 - bits)) & 63];
  return out;
}

function readOrigin(window) {
  try { const o = window.location?.origin; return typeof o === 'string' ? o : null; } catch { return null; }
}

/**
 * `expose: { window: { mode: 'values', allow: { get: ['document.title'], call: ['app.**'] } } }` as the roots, allow-lists (qualified with the root's
 * name: the paths in `expose` are relative to their root) and the rest `exposeObjects` takes. A root named `window` is the window that was passed;
 * any other root names its object. Nothing else is reachable.
 */
function exposedRoots(window, expose) {
  const names = Object.keys(expose);
  if (names.length === 0) throw new TypeError('createPageHost: expose names no root');
  const roots = {};
  const allow = { get: [], call: [], set: [], on: [] };
  const authorizers = new Map();
  const eventFields = {};
  const handles = {};
  const types = {};
  const mcpTools = [];
  let limits;
  for (const name of names) {
    const cfg = expose[name];
    if (!isObj(cfg)) throw new TypeError(`createPageHost: expose.${name} must be { mode, allow }`);
    if (cfg.mode !== undefined && cfg.mode !== 'values' && cfg.mode !== 'handles') throw new TypeError("createPageHost: expose mode must be 'values' (the default) or 'handles'");
    if (typeof cfg.allow === 'string') throw new TypeError('createPageHost: expose allow must be { get, call, set, on }: a wide-open string is not accepted, and the allow-lists apply to handles too');
    // 'handles' is this root's own opt-in; `nodes: true` is a second one, for nodes, windows and documents: control of the page.
    if (cfg.nodes !== undefined && (cfg.mode !== 'handles' || typeof cfg.nodes !== 'boolean')) throw new TypeError(`createPageHost: expose.${name}.nodes is a boolean, and only for mode: 'handles'`);
    if (cfg.wideEntries !== undefined && (cfg.mode !== 'handles' || typeof cfg.wideEntries !== 'boolean')) throw new TypeError(`createPageHost: expose.${name}.wideEntries is a boolean, and only for mode: 'handles'`);
    if (cfg.mode === 'handles') handles[name] = { nodes: cfg.nodes === true, wideEntries: cfg.wideEntries === true };
    const object = cfg.object ?? (name === 'window' ? window : undefined);
    if (object === undefined) throw new TypeError(`createPageHost: expose.${name}: only a root named "window" is the window; give { object } for another root`);
    roots[name] = object;
    for (const [op, list] of Object.entries(cfg.allow ?? {})) {
      if (!(op in allow)) throw new TypeError(`createPageHost: expose.${name}.allow.${op} is not an operation (get, call, set, on)`);
      if (!Array.isArray(list)) throw new TypeError(`createPageHost: expose.${name}.allow.${op} must be an array of path patterns`);
      for (const entry of list) {
        if (typeof entry !== 'string' || entry === '') throw new TypeError(`createPageHost: expose.${name}.allow.${op} entries must be non-empty strings (paths relative to ${name})`);
        // An event source is `path@type`; with no path (`'@hashchange'`) it is the root itself.
        allow[op].push(op === 'on' && entry.startsWith('@') ? `${name}${entry}` : `${name}.${entry}`);
      }
    }
    // Type texts for the far side's `.d.ts`, with the same relative paths (`'app.cart.add'`, `'app.bus@ready'`, `'@hashchange'` for the root itself): host-authored text, checked by `exposeObjects`.
    if (cfg.types !== undefined && !isObj(cfg.types)) throw new TypeError(`createPageHost: expose.${name}.types must be an object of paths`);
    for (const [path, spec] of Object.entries(cfg.types ?? {})) types[path.startsWith('@') ? `${name}${path}` : `${name}.${path}`] = spec;
    for (const [type, fields] of Object.entries(cfg.eventFields ?? {})) eventFields[type] = [...new Set([...(eventFields[type] ?? []), ...(Array.isArray(fields) ? fields : [])])];
    if (cfg.authorize !== undefined) { if (typeof cfg.authorize !== 'function') throw new TypeError(`createPageHost: expose.${name}.authorize must be a function`); authorizers.set(name, cfg.authorize); }
    if (cfg.limits !== undefined) limits = { ...limits, ...cfg.limits };
    // An MCP face for named paths of this root (#219): `mcp: { tools: [{ name, description, call: 'app.cart.add', inputSchema }, { name, description, get: 'document.title' }] }`, paths relative to the root.
    // Off unless written; each tool names one path that the allow-lists above also name. It is served on the `mcp` channel beside the page's WebMCP tools.
    if (cfg.mcp !== undefined) {
      if (!isObj(cfg.mcp) || Object.keys(cfg.mcp).some((k) => k !== 'tools') || !Array.isArray(cfg.mcp.tools)) throw new TypeError(`createPageHost: expose.${name}.mcp must be { tools: [...] }: name each path that becomes a tool (nothing is a tool by being allowed)`);
      for (const tool of cfg.mcp.tools) {
        if (!isObj(tool)) throw new TypeError(`createPageHost: expose.${name}.mcp.tools entries must be objects`);
        const qualify = (v) => (typeof v === 'string' ? `${name}.${v}` : v);
        mcpTools.push({ ...tool, ...(tool.call !== undefined ? { call: qualify(tool.call) } : {}), ...(tool.get !== undefined ? { get: qualify(tool.get) } : {}) });
      }
    }
  }
  const authorize = authorizers.size ? (who, op) => (authorizers.has(op.root) ? authorizers.get(op.root)(who, { ...op, path: op.path }) : true) : undefined;
  return { roots, allow, authorize, limits, eventFields, handles, types, mcp: mcpTools.length ? { tools: mcpTools } : undefined };
}

/**
 * The indicator in the page: one row per connected key, with the key's fingerprint and a Stop control. Exported as `createPageIndicator(window,
 * { name })` for an embedder that serves a session of its own (a mesh adapter) and wants the same badge: `show(who, stop)` adds a row for `who`
 * (its fingerprint) with a Stop button that calls `stop()`, `hide(who)` removes it, `ensure()` puts the badge back if page code took it out,
 * `destroy()` removes everything. BEST EFFORT: it is a DOM element of the page, which page code can remove or cover; Stop, a revoke and the
 * key's capabilities are the controls that hold, not the badge.
 */
function createDomIndicator(window, { name }) {
  const doc = window.document;
  const make = (tag, props = {}, text) => {
    const el = doc.createElement(tag);
    for (const [k, v] of Object.entries(props)) el.setAttribute(k, v);
    if (text !== undefined) el.textContent = text;
    return el;
  };
  let root = null;
  const rows = new Map();
  const attach = () => {
    if (!root) {
      root = make('div', { 'data-wsh-page': 'indicator', role: 'status', 'aria-live': 'polite',
        style: 'position:fixed;right:12px;bottom:12px;z-index:2147483645;box-sizing:border-box;max-width:min(32em,92vw);background:#7a1f1f;color:#fff;border:2px solid #fff;border-radius:8px;padding:8px 12px;font:13px/1.4 system-ui,sans-serif;box-shadow:0 2px 8px rgba(0,0,0,.4)' });
    }
    const parent = doc.body ?? doc.documentElement;
    if (root.parentNode !== parent) parent.appendChild(root);
  };
  return {
    show(who, stop) {
      const row = make('div', { 'data-wsh-page': 'session', 'data-fingerprint': who.fingerprint ?? '', style: 'display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:2px 0' });
      row.appendChild(make('span', {}, `Remote session connected to "${name}" (key`));
      row.appendChild(make('code', { 'data-wsh-page': 'fingerprint', style: 'word-break:break-all' }, who.fingerprint ?? 'unknown'));
      row.appendChild(make('span', {}, ')'));
      const button = make('button', { type: 'button', 'data-wsh-page': 'stop', 'aria-label': `Stop the remote session of key ${who.fingerprint ?? 'unknown'}` }, 'Stop');
      button.addEventListener('click', () => { void stop(); });
      row.appendChild(button);
      rows.set(who.fingerprint, row);
      attach();
      root.appendChild(row);
    },
    hide(who) {
      const row = rows.get(who.fingerprint);
      rows.delete(who.fingerprint);
      try { row?.remove(); } catch { /* gone */ }
      if (rows.size === 0 && root) { try { root.remove(); } catch { /* gone */ } }
    },
    /** Put the indicator back if something in the page took it out while a session is connected. */
    ensure() { if (rows.size && root && !root.isConnected) attach(); },
    destroy() { rows.clear(); try { root?.remove(); } catch { /* gone */ } root = null; },
  };
}

/**
 * @param {object} options
 * @param {object} options.window - REQUIRED: the realm to serve (a page's `window`, an iframe's `contentWindow`, a popup, a worker's
 *   `self`, a fake one in a test). It says where tools are read from, where the indicator is drawn, which `WebSocket` dials the relay,
 *   and whose origin is reported. Passing it exposes nothing by itself.
 * @param {string | { url: string, id?: string }} options.relay - a pipe relay (`@johnhenry/wsh/pipe-relay`): its `ws://` / `wss://` URL, and
 *   optionally the rendezvous id (default: a fresh random one, exposed as `host.rendezvousId`)
 * @param {Record<string, { mode?: 'values', allow?: { get?: string[], call?: string[], set?: string[] }, authorize?: Function, limits?: object, object?: object }>} [options.expose]
 *   object access, off unless written: named roots (`window` is the window passed; another name needs `object`), each with its allow-lists by
 *   operation (paths relative to the root: `'document.title'`, `'app.**'`; nothing allowed by default). `mode: 'handles'` is this root's own opt-in to handles (`nodes: true` a second one, for nodes and the window graph).
 *   See `@johnhenry/wsh/objects` for what `values` mode promises.
 * @param {string} options.name - what this tab is called (shown in the indicator, the `serverInfo` of the MCP server)
 * @param {string | Uint8Array | Array<string | Uint8Array>} options.authorizedKeys - who may log in, as `authorized_keys` lines (with their
 *   options, e.g. `capabilities="mcp:search_products"`) or raw keys. Required and non-empty.
 * @param {{ allow?: string[], approve?: 'never' | 'consequential' | 'always', tools?: object[], prompt?: Function, limits?: object, onCall?: Function, server?: object }} [options.mcp]
 *   the page's WebMCP tools as MCP, see `webmcpTools`. `allow` names the tools; nothing is allowed by default.
 * @param {true | false | { connected(who, control: { stop(): Promise<void> }): void, disconnected(who): void }} [options.indicator=true]
 *   what shows that a remote session is connected. `true`: the badge in `window.document`. Callbacks: for a context with no document
 *   (a worker) or an embedder with its own UI. `false` is refused unless `unattended: true`.
 * @param {boolean} [options.unattended=false] - nobody is in front of this window: `indicator: false` and a window with no document become
 *   allowed, and a call that needs approval is denied unless `mcp.prompt` answers it.
 * @param {CryptoKeyPair | { publicKey: Uint8Array | CryptoKey, sign: Function }} [options.hostKey] - this host's identity. Without one a fresh
 *   non-extractable key is generated: it lives and dies with the page load, so an operator can pin it only for that load (compare
 *   `host.fingerprint`, which the page can show), and a `known_hosts` entry from an earlier load will not match.
 * @param {{ load(): Promise<CryptoKeyPair | undefined | null> | CryptoKeyPair | undefined | null, save(pair: CryptoKeyPair): Promise<void> | void }} [options.hostKeyStore]
 *   persist the generated key through a store you inject (an IndexedDB wrapper: a non-extractable `CryptoKeyPair` can be stored there), so
 *   the page keeps one identity across loads and an operator's TOFU pin holds. Ignored when `hostKey` is given.
 * @param {(who: { username: string, fingerprint: string }) => boolean | void | Promise<boolean | void>} [options.onSession] - a key logged in; return
 *   `false` to refuse it (ask the person first)
 * @param {(who: { username: string, fingerprint: string }) => void} [options.onSessionEnd]
 * @param {(refusal: { reason: string, who: object, detail: string }) => void} [options.onRefused] - as for every host (`REFUSAL_REASONS`)
 * @param {(closed: { reason: string }) => void} [options.onClose] - the host closed itself (the window navigated away or closed) or was closed
 * @param {object} [options.timers] - `{ setTimeout, clearTimeout, setInterval, clearInterval }` of the realm that runs this code, when it is not
 *   the window's own (an opener serving a popup, a parent serving an iframe: the window's timers die with its document)
 * @param {boolean} [options.reconnect=true] - dial the relay again after a session or a failed attempt, so another operator can arrive
 * @param {(line: string) => void} [options.onLog]
 */
export async function createPageHost(options = {}) {
  const { window, relay, name, authorizedKeys, mcp, expose, indicator = true, unattended = false, hostKey, hostKeyStore, onSession, onSessionEnd, onRefused, onClose, reconnect = true, onLog = () => {} } = options;
  if (!window || (typeof window !== 'object' && typeof window !== 'function')) {
    throw new TypeError('createPageHost: window is required: it is the realm served and the only thing this reads (pass `window`, an iframe\'s contentWindow, or a worker\'s self)');
  }
  if (typeof name !== 'string' || !name) throw new TypeError('createPageHost: name is required (what this tab is called)');
  if (typeof unattended !== 'boolean') throw new TypeError('createPageHost: unattended must be true or false');
  if (authorizedKeys === undefined || authorizedKeys === null || (Array.isArray(authorizedKeys) && authorizedKeys.length === 0) || authorizedKeys === '') {
    throw new TypeError('createPageHost: authorizedKeys is required: a page host has no anonymous mode and no password login');
  }
  if (mcp !== undefined && !isObj(mcp)) throw new TypeError('createPageHost: mcp must be an object { allow: [...tool names] }');
  if (expose !== undefined && !isObj(expose)) throw new TypeError('createPageHost: expose must be an object of named roots: { window: { mode: \'values\', allow: { get: [...] } } }');
  if (mcp === undefined && expose === undefined) throw new TypeError('createPageHost: nothing to serve: pass mcp: { allow: [...tool names] } and/or expose: { window: { allow } }');
  const exposed = expose === undefined ? null : exposedRoots(window, expose);
  const doc = window.document ?? null;
  const callbacks = isObj(indicator) ? indicator : null;
  if (callbacks && (typeof callbacks.connected !== 'function' || typeof callbacks.disconnected !== 'function')) throw new TypeError('createPageHost: indicator callbacks need connected(who, control) and disconnected(who)');
  if (indicator !== true && indicator !== false && !callbacks) throw new TypeError('createPageHost: indicator must be true, false or { connected, disconnected }');
  if (indicator === false && !unattended) throw new TypeError('createPageHost: indicator: false is refused unless unattended: true (a remote session must be visible to the person at the page)');
  if (indicator === true && !doc) {
    if (!unattended) throw new TypeError('createPageHost: this window has no document to draw the indicator in: supply indicator callbacks, or say unattended: true');
  }
  if (!doc && !unattended && !callbacks) throw new TypeError('createPageHost: this window has no document: supply indicator callbacks, or say unattended: true');
  if ((mcp || exposed?.mcp) && (mcp?.approve ?? 'consequential') !== 'never' && !doc && !mcp?.prompt && !unattended) {
    throw new TypeError("createPageHost: this window has no document to ask the person in: supply mcp.prompt, mcp.approve: 'never', or unattended: true");
  }
  if (typeof window.WebSocket !== 'function') throw new TypeError('createPageHost: window.WebSocket is needed to dial the relay');
  for (const [k, fn] of Object.entries({ onSession, onSessionEnd, onRefused, onClose })) if (fn !== undefined && typeof fn !== 'function') throw new TypeError(`createPageHost: ${k} must be a function`);
  if (hostKeyStore !== undefined && (typeof hostKeyStore?.load !== 'function' || typeof hostKeyStore?.save !== 'function')) throw new TypeError('createPageHost: hostKeyStore needs load() and save(keyPair)');

  const relayOptions = typeof relay === 'string' ? { url: relay } : relay;
  if (!isObj(relayOptions) || typeof relayOptions.url !== 'string') throw new TypeError('createPageHost: relay is required: the ws:// or wss:// URL of a pipe relay (or { url, id })');
  const rendezvousId = relayOptions.id ?? randomRendezvousId(window.crypto);
  const hostUrl = pipeUrl(relayOptions.url, rendezvousId, 'host');
  const operatorUrl = pipeUrl(relayOptions.url, rendezvousId, 'operator');

  const timers = timersOf(window, options.timers);
  const origin = readOrigin(window);
  if (origin === null) throw new TypeError('createPageHost: cannot read window.location.origin: the host closes when the window leaves its origin, so it needs to know it');

  // The host's identity.
  let keyOption = hostKey;
  if (keyOption === undefined) {
    let pair = hostKeyStore ? await hostKeyStore.load() : undefined;
    if (!pair) {
      pair = await generateKeyPair(false);
      if (hostKeyStore) await hostKeyStore.save(pair);
    }
    keyOption = pair;
  }
  const hostFingerprint = (await resolveHostKey(keyOption, 'createPageHost: hostKey')).fingerprint;

  const callbacksUi = callbacks ?? (indicator === true && doc ? createDomIndicator(window, { name }) : null);
  const control = (who) => ({ stop: () => host.revoke(who.fingerprint) });

  /** @type {{ who: object, since: number, socket: object } | null} */
  let current = null;
  let halfSocket = null;
  const revoked = new Set();
  let closed = false;
  let closedReason = null;
  let backoff = RECONNECT_START_MS;
  let redialTimer = null;
  let watch = null;
  let unlisten = null;

  const objectsHandler = exposed ? exposeObjects({
    roots: exposed.roots, allow: exposed.allow, authorize: exposed.authorize, limits: exposed.limits, eventFields: exposed.eventFields, handles: exposed.handles, types: exposed.types, mcp: exposed.mcp, timers,
    // Handle ids come from the served window's own CSPRNG.
    random: (n) => window.crypto.getRandomValues(new Uint8Array(n)),
    guard: () => gone(),
  }) : null;
  // The tools of the `mcp` channel: the page's WebMCP tools (`mcp.allow`) and the paths the host named as tools (`expose.ROOT.mcp.tools`). One handler, so one approval, one set of
  // bounds, one label; a tool made from a path is allowed by being named in `expose`, and still needs the key's `mcp:TOOL` and `objects:ROOT:OP` capabilities.
  const objectTools = objectsHandler?.mcpTools ?? [];
  const mcpHandler = mcp || objectTools.length ? webmcpTools({
    ...(mcp ?? {}), window, timers: options.timers, server: { name, ...(mcp?.server ?? {}) },
    allow: [...(mcp?.allow ?? []), ...(objectsHandler?.mcpToolNames ?? [])],
    tools: [...(mcp?.tools ?? []), ...objectTools],
    // Nobody is in front of an unattended window: without a prompt of the embedder's, what needs approval is denied.
    prompt: mcp?.prompt ?? (unattended ? () => false : undefined),
    guard: () => gone() ?? mcp?.guard?.() ?? null,
  }) : null;
  /** What each handler tells and ends: the sessions of a key, or all of them. */
  const closeSessions = async (reason, fingerprint) => {
    const counts = await Promise.all([mcpHandler, objectsHandler].filter(Boolean).map((h) => h.closeSessions(reason, fingerprint).catch(() => 0)));
    return Math.max(0, ...counts);
  };

  const memory = createMemoryHost({
    auth: {
      authorizedKeys,
      async authorize(who) {
        if (closed || revoked.has(who.fingerprint) || !halfSocket) return false;
        try { if (onSession && (await onSession({ username: who.username, fingerprint: who.fingerprint })) === false) return false; } catch (e) { onLog(`onSession threw: ${e?.message ?? e}`); return false; }
        if (closed || revoked.has(who.fingerprint)) return false;
        begin(who);
        return true;
      },
    },
    hostKey: keyOption,
    dataStreams: false,
    sealSession: 'require',
    rpc: { ...(mcpHandler ? { mcp: mcpHandler } : {}), ...(objectsHandler ? { [OBJECTS_PROTOCOL]: objectsHandler } : {}) },
    onRefused,
    onLog,
  });

  function begin(who) {
    const w = { username: who.username, fingerprint: who.fingerprint };
    current = { who: w, since: Date.now(), socket: halfSocket };
    backoff = RECONNECT_START_MS;
    try { callbacksUi?.show?.(w, control(w).stop); callbacksUi?.connected?.(w, control(w)); } catch (e) { onLog(`indicator threw: ${e?.message ?? e}`); }
  }
  function end() {
    if (!current) return;
    const { who } = current;
    current = null;
    try { callbacksUi?.hide?.(who); callbacksUi?.disconnected?.(who); } catch (e) { onLog(`indicator threw: ${e?.message ?? e}`); }
    try { onSessionEnd?.(who); } catch (e) { onLog(`onSessionEnd threw: ${e?.message ?? e}`); }
  }

  /** Why this window can no longer be served, or null. */
  function gone() {
    if (closedReason) return closedReason;
    try { if (window.closed === true) return 'the window was closed'; } catch { return 'the window was closed'; }
    if (readOrigin(window) !== origin) return 'the window navigated to another origin';
    return null;
  }

  function dial() {
    if (closed) return;
    let socket;
    try { socket = new window.WebSocket(hostUrl); } catch (e) { onLog(`dialing the relay failed: ${e?.message ?? e}`); schedule(false); return; }
    halfSocket = socket;
    onLog('dialed the relay, waiting for an operator');
    let served = false;
    void memory.accept(socket, { remote: { address: 'relay' } }).catch((e) => onLog(`accept failed: ${e?.message ?? e}`));
    const onEnd = () => {
      if (halfSocket === socket) halfSocket = null;
      served = current?.socket === socket;
      if (served) end();
      schedule(served);
    };
    socket.addEventListener('close', onEnd);
  }
  function schedule(afterSession) {
    if (closed || !reconnect || redialTimer !== null) return;
    const delay = afterSession ? 0 : backoff;
    if (!afterSession) backoff = Math.min(backoff * 2, RECONNECT_MAX_MS);
    redialTimer = timers.setTimeout(() => { redialTimer = null; dial(); }, delay);
  }

  async function shutdown(reason, { tell = true } = {}) {
    if (closed) return;
    closedReason = reason;
    if (tell) await closeSessions(reason).catch(() => {});
    closed = true;
    timers.clearTimeout(redialTimer);
    if (watch !== null) timers.clearInterval(watch);
    try { unlisten?.(); } catch { /* the window is gone */ }
    try { halfSocket?.close(1000); } catch { /* already closed */ }
    end();
    callbacksUi?.destroy?.();
    await memory.close();
    try { onClose?.({ reason }); } catch (e) { onLog(`onClose threw: ${e?.message ?? e}`); }
  }

  const host = {
    /** The URL an operator dials (its rendezvous id is the secret that pairs it with this page). */
    operatorUrl,
    rendezvousId,
    /** What the page serves: its name and the origin it was started in. */
    name,
    origin,
    /** This host's key: compare it with what the operator sees (`client.hostKey.fingerprint`) to pin it. New on every page load unless a key or a `hostKeyStore` was given. */
    fingerprint: hostFingerprint,
    /** Who is connected now: `[{ username, fingerprint, since }]`. */
    get sessions() { return current ? [{ ...current.who, since: current.since }] : []; },
    get closed() { return closed; },
    /** Why the host closed itself, or null. */
    get closedReason() { return closedReason; },
    /**
     * End the session of a key and refuse that key until this host is closed (a Stop that lets the same operator straight back in is
     * not a Stop). The operator is told why before the channel ends. Resolves true if a session was ended.
     */
    async revoke(fingerprint) {
      revoked.add(fingerprint);
      const n = await closeSessions('the person at the page stopped this session', fingerprint);
      if (current?.who.fingerprint === fingerprint) { try { current.socket.close(1000); } catch { /* gone */ } }
      return n > 0 || current?.who.fingerprint === fingerprint;
    },
    /** End every session, close the relay connection and stop serving. */
    close: () => shutdown('the page host was closed'),
  };

  // The window going away: a navigation, a close, a different origin. Events where the window sends them, and a check every second
  // and before every call, for the cases it cannot (an iframe that navigated cross-origin, a popup that closed).
  const leave = () => { void shutdown(gone() ?? 'the window was unloaded'); };
  try { window.addEventListener?.('pagehide', leave); unlisten = () => window.removeEventListener?.('pagehide', leave); } catch { /* a window that takes no listeners: the check below covers it */ }
  watch = timers.setInterval(() => {
    const why = gone();
    if (why) void shutdown(why);
    else callbacksUi?.ensure?.();
  }, WATCH_MS);

  dial();
  return host;
}
