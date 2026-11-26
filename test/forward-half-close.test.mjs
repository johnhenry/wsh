// test/forward-half-close.test.mjs -- a local socket that half-closes and keeps reading still gets what the far side
// sends later (#271), through every forward the JS client builds: unix and TCP listeners to a TCP port, a unix socket
// and a named endpoint, and the reverse forwards (the host listens, this client serves). Real sockets in a temp dir.
import { describe, it, before, after, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { generateKeyPair, exportPublicKeyRaw } from '@johnhenry/wsh';
import { fixture, sleep, listen } from './gateway-fixture.mjs';

const MiB = 1024 * 1024;
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const bulk = (n) => { const b = Buffer.alloc(n); for (let i = 0; i < b.length; i += 4096) b.writeUInt32LE(i, i); return b; };
const connectUnix = (p) => new Promise((resolve, reject) => { const s = net.connect({ path: p, allowHalfOpen: true }); s.once('connect', () => resolve(s)); s.once('error', reject); });
const connectTcp = (port) => new Promise((resolve, reject) => { const s = net.connect({ host: '127.0.0.1', port, allowHalfOpen: true }); s.once('connect', () => resolve(s)); s.once('error', reject); });
/** Everything a socket delivers until the far side ends it. */
const readAll = (s) => new Promise((resolve) => { const cs = []; s.on('data', (c) => cs.push(c)); s.on('error', () => {}); s.on('end', () => resolve(Buffer.concat(cs))); s.on('close', () => resolve(Buffer.concat(cs))); });
/** An origin that waits `delayMs` after the client's FIN and then answers. */
const delayedOrigin = (delayMs, reply) => net.createServer({ allowHalfOpen: true }, (s) => {
  s.on('error', () => {}); s.on('end', () => setTimeout(() => { if (!s.destroyed) s.end(reply); }, delayMs)); s.resume();
});

describe('forwards: the local side half-closes at once and keeps reading', () => {
  const fx = fixture();
  let dir; let n = 0;
  const forwards = []; const socks = [];
  const tmp = () => { dir ??= fs.mkdtempSync(path.join(os.tmpdir(), 'wsh-fh-')); return fs.realpathSync(dir); };
  const sockPath = () => path.join(tmp(), `s${n++}.sock`);
  afterEach(async () => {
    for (const s of socks.splice(0)) s.destroy();
    for (const f of forwards.splice(0)) await f.close().catch(() => {});
    await fx.teardown();
    if (dir) { fs.rmSync(dir, { recursive: true, force: true }); dir = undefined; } // a directory this test made
  });
  const track = (f) => { forwards.push(f); return f; };
  const track2 = (s) => { socks.push(s); return s; };

  it('local unix socket -> remote TCP port: an answer 2.5 s after the half-close arrives', async () => {
    const origin = delayedOrigin(2500, 'tcp done\n');
    const port = await listen(origin); fx.nets.push(origin);
    const { client } = await fx.setup({ allow: [`127.0.0.1:${port}`] });
    const local = sockPath();
    track(await client.forwardUnix({ local, remote: `127.0.0.1:${port}` }));
    const s = track2(await connectUnix(local));
    s.end();
    assert.equal((await readAll(s)).toString(), 'tcp done\n');
  });

  it('local TCP port -> remote unix socket: an answer 2.5 s after the half-close arrives', async () => {
    const remote = sockPath();
    const origin = delayedOrigin(2500, 'unix done\n');
    await new Promise((r) => origin.listen(remote, r)); fx.nets.push(origin);
    const { client } = await fx.setup({ allow: [], unix: { connect: [remote] } });
    const fwd = track(await client.forwardUnix({ local: '127.0.0.1:0', remote }));
    const s = track2(await connectTcp(fwd.address.port));
    s.end();
    assert.equal((await readAll(s)).toString(), 'unix done\n');
  });

  it('the host\'s answer after the half-close is not cut at 20 MiB either, with the local reader slow to start', async () => {
    const data = bulk(20 * MiB);
    const origin = net.createServer({ allowHalfOpen: true }, (s) => { s.on('error', () => {}); s.on('end', () => s.end(data)); s.resume(); });
    const port = await listen(origin); fx.nets.push(origin);
    const { client } = await fx.setup({ allow: [`127.0.0.1:${port}`] });
    const local = sockPath();
    track(await client.forwardUnix({ local, remote: `127.0.0.1:${port}` }));
    const s = track2(await connectUnix(local));
    s.pause();
    s.end();
    await sleep(1500);
    s.resume();
    const got = await readAll(s);
    assert.equal(got.length, data.length);
    assert.equal(sha(got), sha(data));
  });

  describe('a named endpoint on an in-page host', () => {
    let host; let keyPair;
    before(async () => {
      keyPair = await generateKeyPair(true);
      host = createMemoryHost({
        auth: { authorizedKeys: [await exportPublicKeyRaw(keyPair.publicKey)] },
        endpoints: {
          // reads to the client's EOF, waits, and only then answers
          slow: async (d) => {
            const r = d.readable.getReader(); const w = d.writable.getWriter();
            for (;;) { const { done } = await r.read(); if (done) break; }
            await sleep(2500);
            await w.write(new TextEncoder().encode('endpoint done\n'));
            await w.close();
          },
          big: async (d) => {
            const r = d.readable.getReader(); const w = d.writable.getWriter();
            for (;;) { const { done } = await r.read(); if (done) break; }
            const b = bulk(20 * MiB);
            for (let o = 0; o < b.length; o += 65536) await w.write(b.subarray(o, o + 65536));
            await w.close();
          },
        },
      });
    });
    after(() => host.close());

    it('forwardEndpoint: an answer 2.5 s after the half-close arrives', async () => {
      const client = await host.connect({ username: 'alice', keyPair });
      fx.clients.push(client);
      const local = sockPath();
      track(await client.forwardEndpoint({ local, endpoint: 'slow' }));
      const s = track2(await connectUnix(local));
      s.end();
      assert.equal((await readAll(s)).toString(), 'endpoint done\n');
    });

    it('forwardEndpoint: a 20 MiB answer after the half-close arrives whole with a late reader', async () => {
      const client = await host.connect({ username: 'alice', keyPair });
      fx.clients.push(client);
      const local = sockPath();
      track(await client.forwardEndpoint({ local, endpoint: 'big' }));
      const s = track2(await connectUnix(local));
      s.pause();
      s.end();
      await sleep(1500);
      s.resume();
      const got = await readAll(s);
      assert.equal(got.length, 20 * MiB);
      assert.equal(sha(got), sha(bulk(20 * MiB)));
    });
  });

  it('reverse forward (the host listens on a unix socket, this client serves a local TCP service): an answer 2.5 s after the connector half-closed arrives', async () => {
    const service = delayedOrigin(2500, 'reverse unix done\n');
    const servicePort = await listen(service); fx.nets.push(service);
    const hostSock = sockPath();
    const { client } = await fx.setup({ allow: [], unix: { listen: [hostSock] } });
    track(await client.forwardUnix({ local: `127.0.0.1:${servicePort}`, remote: hostSock, reverse: true }));
    const s = track2(await connectUnix(hostSock));
    s.end();
    assert.equal((await readAll(s)).toString(), 'reverse unix done\n');
  });

  it('reverse TCP listener (listenTcp): an answer 2.5 s after the connector half-closed arrives', async () => {
    const { client } = await fx.setup({ allow: [], reverse: {} });
    const handle = await client.listenTcp(0, {
      onConnection: async (d) => {
        const r = d.readable.getReader(); const w = d.writable.getWriter();
        for (;;) { const { done } = await r.read(); if (done) break; }
        await sleep(2500);
        await w.write(new TextEncoder().encode('reverse tcp done\n'));
        await w.close();
      },
    });
    const s = track2(await connectTcp(handle.port));
    s.end();
    assert.equal((await readAll(s)).toString(), 'reverse tcp done\n');
  });

  it('reverse TCP listener: the connector sends after the client side finished, 2.5 s later, and it arrives', async () => {
    const { client } = await fx.setup({ allow: [], reverse: {} });
    const got = [];
    let done; const finished = new Promise((r) => { done = r; });
    const handle = await client.listenTcp(0, {
      onConnection: async (d) => {
        const r = d.readable.getReader(); const w = d.writable.getWriter();
        await w.write(new TextEncoder().encode('hello'));
        await w.close(); // we are done sending; we keep reading
        for (;;) { const { value, done: eof } = await r.read(); if (eof) break; got.push(Buffer.from(value)); }
        done();
      },
    });
    const s = track2(await connectTcp(handle.port));
    assert.equal((await readAll(s)).toString(), 'hello');
    await sleep(2500);
    s.end('from the connector');
    await finished;
    assert.equal(Buffer.concat(got).toString(), 'from the connector');
  });
});
