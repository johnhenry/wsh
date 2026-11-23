/**
 * `client.forwardUnix({ local, remote })` for Node: the `ssh -L` / `ssh -R` shapes with unix sockets and TCP ports
 * mixed. Loaded on demand by `WshClient#forwardUnix` so the browser build never sees `node:*`.
 */

import net from 'node:net';
import fsp from 'node:fs/promises';
import { once } from 'node:events';

/** `/path`, `./path`, `@abstract` are sockets; anything else is `host:port` (also `[::1]:80`, or a bare port = 127.0.0.1). */
export function parseEndpoint(spec) {
  if (typeof spec !== 'string' || !spec) throw new TypeError('forwardUnix: an endpoint must be a non-empty string');
  if (spec.startsWith('/') || spec.startsWith('./') || spec.startsWith('../') || spec.startsWith('@')) return { kind: 'unix', path: spec };
  if (/^\d{1,5}$/.test(spec)) return { kind: 'tcp', host: '127.0.0.1', port: Number(spec) };
  const m = /^(?:\[([^\]]+)\]|([^:]+)):(\d{1,5})$/.exec(spec);
  if (!m) throw new TypeError(`forwardUnix: ${JSON.stringify(spec)} is neither a socket path nor host:port`);
  const port = Number(m[3]);
  if (port > 65535) throw new TypeError(`forwardUnix: bad port in ${JSON.stringify(spec)}`);
  return { kind: 'tcp', host: m[1] ?? m[2], port };
}

/** Pipe a net.Socket and a gateway duplex both ways with backpressure on each leg. */
function pipe(sock, duplex) {
  const writer = duplex.writable.getWriter();
  const reader = duplex.readable.getReader();
  sock.on('data', (d) => {
    sock.pause();
    writer.write(new Uint8Array(d.buffer, d.byteOffset, d.length)).then(() => { if (!sock.destroyed) sock.resume(); }, () => sock.destroy());
  });
  sock.on('end', () => { void writer.close().catch(() => {}); });
  sock.on('error', () => {});
  sock.on('close', () => { duplex.destroy(); });
  (async () => {
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        if (!sock.write(value)) await once(sock, 'drain');
      }
      sock.end();
    } catch { sock.destroy(); }
  })();
  duplex.closed.then(() => { if (!sock.destroyed) sock.end(); });
}

async function listenLocal(spec, { replace }) {
  const server = net.createServer({ pauseOnConnect: true });
  if (spec.kind === 'tcp') {
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen({ host: spec.host, port: spec.port }, () => { server.off('error', reject); resolve(); }); });
    return { server, cleanup: async () => {} };
  }
  if (spec.path.startsWith('@')) throw new TypeError('forwardUnix: a local abstract socket is not supported; use a path');
  let existing = null;
  try { existing = await fsp.lstat(spec.path); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  if (existing) {
    if (!existing.isSocket()) throw new Error(`${spec.path} exists and is not a socket`);
    if (!replace) throw new Error(`${spec.path} already exists (pass replace: true to replace a stale socket)`);
    const live = await new Promise((resolve) => {
      const p = net.connect({ path: spec.path });
      p.once('connect', () => { p.destroy(); resolve(true); });
      p.once('error', (e) => resolve(e.code !== 'ECONNREFUSED' && e.code !== 'ENOENT'));
    });
    if (live) throw new Error(`${spec.path} is in use`);
    await fsp.unlink(spec.path);
  }
  const old = (() => { try { return process.umask(0o177); } catch { return null; } })();
  try {
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen({ path: spec.path }, () => { server.off('error', reject); resolve(); }); });
  } finally { if (old !== null) process.umask(old); }
  await fsp.chmod(spec.path, 0o600);
  const st = await fsp.lstat(spec.path);
  return {
    server,
    cleanup: async () => { try { const now = await fsp.lstat(spec.path); if (now.isSocket() && now.ino === st.ino) await fsp.unlink(spec.path); } catch { /* gone */ } },
  };
}

/**
 * @param {import('./client.mjs').WshClient} client
 * @param {{ local: string, remote: string, reverse?: boolean, replace?: boolean, onError?: (err: Error) => void }} opts
 */
export async function forward(client, { local, remote, reverse = false, replace = false, onError = () => {} } = {}) {
  const l = parseEndpoint(local);
  const r = parseEndpoint(remote);

  if (reverse) {
    if (r.kind !== 'unix') throw new TypeError('forwardUnix: with reverse: true the remote end must be a socket path (the host listens on it)');
    const handle = await client.listenUnix(r.path, {
      replace,
      onConnection: (duplex) => {
        const sock = l.kind === 'unix' ? net.connect({ path: l.path }) : net.connect({ host: l.host, port: l.port });
        sock.pause();
        sock.once('connect', () => { pipe(sock, duplex); sock.resume(); });
        sock.once('error', (e) => { duplex.destroy(); onError(e); });
      },
    });
    return { local, remote, close: () => handle.close() };
  }

  const { server, cleanup } = await listenLocal(l, { replace });
  const open = r.kind === 'unix' ? () => client.openUnix(r.path) : () => client.openTcp(r.host, r.port);
  server.on('connection', async (sock) => {
    sock.on('error', () => {});
    let duplex;
    try { duplex = await open(); } catch (e) { sock.destroy(); onError(e); return; }
    if (sock.destroyed) { duplex.destroy(); return; }
    pipe(sock, duplex);
    sock.resume();
  });
  server.on('error', onError);
  return {
    local, remote, address: server.address(),
    async close() {
      await new Promise((res) => { server.close(() => res()); server.closeAllConnections?.(); });
      await cleanup();
    },
  };
}
