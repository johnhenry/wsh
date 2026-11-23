// What the test page loads: the package's browser entry points, handed to the tests on `window.wsh`, plus a few small
// helpers (`window.h`) so a spec's `page.evaluate` bodies stay short. Nothing here is under test except the package.
import * as client from '../../src/index.mjs';
import * as memory from '../../src/memory-host.mjs';
import * as host from '../../src/host.mjs';
import * as reverse from '../../src/reverse-host.mjs';

const wsh = { ...client, ...memory, ...host, ...reverse };
window.wsh = wsh;

const dec = new TextDecoder();
const enc = new TextEncoder();
const keys = new Map();
const clients = new Map();
const sessions = new Map();
let counter = 0;

/** Record a session's output as text. */
function record(session) {
  const rec = { text: '', exit: undefined, closed: false, session };
  session.onData = (d) => { rec.text += dec.decode(d); };
  session.onExit = (c) => { rec.exit = c; };
  session.onClose = () => { rec.closed = true; };
  const id = `s${++counter}`;
  sessions.set(id, rec);
  return id;
}

window.h = {
  enc, dec,
  /** Make a key pair held by the page (non-extractable unless asked); returns its authorized_keys line. */
  async newKey(name = 'k', { extractable = false } = {}) {
    const kp = await wsh.generateKeyPair(extractable);
    keys.set(name, kp);
    return wsh.exportPublicKeySSH(kp.publicKey);
  },
  key: (name = 'k') => keys.get(name),
  /** Connect a client over the page's own WebSocket; returns its id. */
  async connect(url, { key = 'k', username = 'alice', ...options } = {}) {
    const transport = new wsh.WebSocketTransport();
    const c = new wsh.WshClient({ transportFactories: { ws: () => transport } });
    await c.connect(url, { username, keyPair: keys.get(key), transport: 'ws', ...options });
    const id = ++counter;
    clients.set(id, { client: c, transport });
    return id;
  },
  client: (id) => clients.get(id).client,
  /** The network goes away with no Close frame (what a resume is for). */
  drop: (id) => clients.get(id).transport.close(),
  async disconnect(id) { await clients.get(id).client.disconnect(); clients.delete(id); },
  /** Open a session and record its output; returns the recorder's id. */
  async open(id, options) {
    const session = await clients.get(id).client.openSession(options);
    return record(session);
  },
  recorder: (sid) => { const r = sessions.get(sid); return { text: r.text, exit: r.exit, closed: r.closed, seq: r.session.seq, sessionId: r.session.sessionId, dataMode: r.session.dataMode }; },
  session: (sid) => sessions.get(sid).session,
  resumeToken: (sid) => Array.from(sessions.get(sid).session.resumeToken),
  async resume(id, sessionId, token, lastSeq) {
    const { session } = await clients.get(id).client.resumeSession(sessionId, new Uint8Array(token), { lastSeq });
    const sid = `s${++counter}`;
    const rec = { text: '', exit: undefined, closed: false, session };
    session.onData = (d) => { rec.text += dec.decode(d); };
    session.onExit = (c) => { rec.exit = c; };
    session.onClose = () => { rec.closed = true; };
    sessions.set(sid, rec);
    return sid;
  },
};
// ── A host that lives in the page ───────────────────────────────────────────────────────────────────────────────────────
// Backends a page could really have: an exec function, a pty that echoes (no node-pty in a browser), an in-memory file
// system. Everything they are asked is recorded so a spec can check what reached them.
const hosts = new Map();

function memoryFs(initial) {
  const files = new Map(Object.entries(initial).map(([k, v]) => [k, enc.encode(v)]));
  const fail = (m) => Object.assign(new Error(m), { wsh: true });
  return {
    files,
    maxFileBytes: 1 << 20,
    async operate(op, path, { offset, length, newPath } = {}) {
      switch (op) {
        case 'list': return { entries: [...files].map(([name, d]) => ({ name: name.replace(/^\//, ''), size: d.byteLength, modified: 0, type: 'file' })), metadata: { path } };
        case 'stat': { const d = files.get(path); if (!d) throw fail('no such file'); return { metadata: { name: path, size: d.byteLength, modified: 0, type: 'file' } }; }
        case 'read': { const d = files.get(path); if (!d) throw fail('no such file'); return { metadata: { data: d.subarray(offset ?? 0, (offset ?? 0) + (length ?? d.byteLength)), size: d.byteLength } }; }
        case 'remove': files.delete(path); return { metadata: { removed: path } };
        case 'rename': files.set(newPath, files.get(path)); files.delete(path); return { metadata: { renamed: path, to: newPath } };
        default: throw fail(`${op} is not offered`);
      }
    },
    async readWhole(path) { const d = files.get(path); if (!d) throw fail('no such file'); return d; },
    async writeWhole(path, data) { files.set(path, data.slice()); },
    async writeAt(path, data) { files.set(path, data.slice()); },
  };
}

/** Named endpoints a page can offer: `echo` sends back what it receives; `count` reads to the end and answers with the byte count. */
function pageEndpoints(record) {
  return {
    echo: async (duplex) => { record.opened.push({ name: 'echo', user: duplex.who.username }); await duplex.readable.pipeTo(duplex.writable); },
    count: async (duplex) => {
      record.opened.push({ name: 'count', user: duplex.who.username });
      let n = 0;
      const reader = duplex.readable.getReader();
      for (;;) { const { done, value } = await reader.read(); if (done) break; n += value.byteLength; }
      const writer = duplex.writable.getWriter();
      await writer.write(enc.encode(String(n)));
      await writer.close();
    },
    private: { open: async (duplex) => { await duplex.writable.close(); }, authorize: (who) => who.username === 'root' },
  };
}

window.h.startHost = async ({ authorizedKeys, dataStreams, hostKey, sessions = false, initialFiles = {}, endpoints = false } = {}) => {
  const log = [];
  const record = { opened: [] };
  const ptyCalls = [];
  const fs = memoryFs(initialFiles);
  let hostKeyOption;
  let hostKeyPair = null;
  if (hostKey === 'pair' || hostKey === 'signer') {
    hostKeyPair = await wsh.generateKeyPair(false); // non-extractable: the page can sign with it but never read it
    hostKeyOption = hostKey === 'pair' ? hostKeyPair
      : { publicKey: await wsh.exportPublicKeyRaw(hostKeyPair.publicKey), sign: (d) => wsh.sign(hostKeyPair.privateKey, d) };
  }
  const host = wsh.createMemoryHost({
    // Each entry is an authorized_keys line or the raw key bytes a spec sends as an array of numbers.
    auth: { authorizedKeys: authorizedKeys.map((a) => (typeof a === 'string' ? a : new Uint8Array(a))) },
    exec: async (command, io) => {
      if (command === 'cat') {
        io.onInput((bytes) => { void io.write(bytes); });
        await new Promise((resolve) => io.onInputEnd(resolve));
        return 0;
      }
      await io.write(`ran:${command}\n`);
      return 3;
    },
    pty: {
      shell: 'page-shell',
      spawn: (file, args, o) => {
        ptyCalls.push({ spawn: [file, o.cols, o.rows] });
        let onData; let onExit;
        return {
          onData: (cb) => { onData = cb; }, onExit: (cb) => { onExit = cb; },
          write: (d) => { ptyCalls.push({ write: d instanceof Uint8Array, text: typeof d === 'string' ? d : dec.decode(d) }); onData(`pty-echo:${typeof d === 'string' ? d : dec.decode(d)}`); },
          resize: (c, r) => ptyCalls.push({ resize: [c, r] }),
          kill: () => onExit({ exitCode: 0 }),
        };
      },
    },
    fs,
    hostKey: hostKeyOption,
    sessions: sessions || undefined,
    endpoints: endpoints ? pageEndpoints(record) : undefined,
    dataStreams,
    onLog: (l) => log.push(l),
  });
  const id = `h${++counter}`;
  hosts.set(id, { host, log, ptyCalls, fs, hostKeyPair, record });
  return id;
};
/** Serve a WebSocket this page opens to `url` (the byte pipe): `accept(new WebSocket(url))`, the socket still connecting. */
window.h.serve = async (id, url, options) => {
  const socket = new WebSocket(url);
  await hosts.get(id).host.accept(socket, options);
  return socket.readyState;
};
window.h.hostInfo = async (id) => {
  const { log, ptyCalls, fs, hostKeyPair, record } = hosts.get(id);
  return {
    log, ptyCalls, endpointsOpened: record.opened, files: Object.fromEntries([...fs.files].map(([k, v]) => [k, dec.decode(v)])),
    hostFingerprint: hostKeyPair ? await wsh.fingerprint(await wsh.exportPublicKeyRaw(hostKeyPair.publicKey)) : null,
    bufferType: typeof Buffer,
  };
};
window.h.stopHost = (id) => hosts.get(id).host.close();

window.wshReady = true;
