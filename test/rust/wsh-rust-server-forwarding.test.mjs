// test/rust/wsh-rust-server-forwarding.test.mjs -- #145: the Rust `wsh-server` against this repo's JS client for the
// forwarding messages the Node host serves: GatewayCredit flow control, OpenUnix and ListenUnix with the same
// policy (these are the cases of test/gateway-unix.test.mjs and test/gateway-flow-control.test.mjs, run over the real
// Rust binary).
//
// Real sockets in a temp directory; the "Docker API" is a fake HTTP server on a unix socket -- never a real daemon,
// nothing under the user's home. Every server runs with HOME in a scratch directory.
//
// Prerequisite: `cargo build --release -p wsh-server` (or WSH_SERVER_BIN).

import { describe, it, before, after, afterEach } from 'node:test';
import './helpers/guard.mjs';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import net from 'node:net';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { WshClient, generateKeyPair, exportPublicKeySSH, MSG } from '../../src/index.mjs';
import { GatewayError } from '../../src/gateway-client.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SERVER_BIN = process.env.WSH_SERVER_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh-server');
const MiB = 1024 * 1024;
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(cond, what, ms = 5000) {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(10); }
}
const exists = (p) => fs.existsSync(p);
const listenUnixSock = (server, p) => new Promise((resolve, reject) => { server.once('error', reject); server.listen(p, () => resolve()); });
const listenTcp = (server) => new Promise((r) => server.listen(0, '127.0.0.1', () => r(server.address().port)));
const freePort = () => new Promise((resolve) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); }); });

const ORIGINAL_TLS_REJECT = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
before(() => {
  assert.ok(exists(SERVER_BIN), `expected the built binary at ${SERVER_BIN} (cargo build --release -p wsh-server, or WSH_SERVER_BIN)`);
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // the dev certificate is self-signed
});
after(() => {
  if (ORIGINAL_TLS_REJECT === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  else process.env.NODE_TLS_REJECT_UNAUTHORIZED = ORIGINAL_TLS_REJECT;
});

/** Read a duplex to its end. */
async function readAll(duplex) {
  const chunks = [];
  const reader = duplex.readable.getReader();
  for (;;) { const { value, done } = await reader.read(); if (done) break; chunks.push(value); }
  return Buffer.concat(chunks);
}

const toml = (list) => `[${list.map((s) => JSON.stringify(s)).join(', ')}]`;

describe('Rust wsh-server: gateway credit, unix sockets and listeners (the Node host\'s cases)', () => {
  const procs = [];
  const clients = [];
  const closers = [];
  const dirs = [];
  let dir;
  /** A scratch directory, resolved (macOS /var -> /private/var) and short enough for a socket path. */
  const tmp = () => { if (!dir) { dir = fs.mkdtempSync(path.join('/tmp', 'wsh-fw-')); dirs.push(dir); } return fs.realpathSync(dir); };

  afterEach(async () => {
    for (const c of clients.splice(0)) await c.disconnect().catch(() => {});
    for (const f of closers.splice(0)) await f();
    for (const p of procs.splice(0)) { p.kill(); await new Promise((r) => { if (p.exitCode !== null) r(); else { p.once('exit', r); setTimeout(r, 2000); } }); }
    for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true }); // directories this test made
    dir = undefined;
  });

  /**
   * Start a real wsh-server and connect the JS client. `gateway` mirrors the Node host's option: `allow`,
   * `unix: { connect, listen, replaceStale, maxListeners }`, `maxConnections`, `maxBufferedBytes`, ...
   */
  async function setup(gateway) {
    const kp = await generateKeyPair(true);
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wsh-fw-home-'));
    dirs.push(home);
    fs.mkdirSync(path.join(home, '.wsh'));
    fs.writeFileSync(path.join(home, '.wsh', 'authorized_keys'), `${await exportPublicKeySSH(kp.publicKey)}\n`);
    const u = gateway.unix ?? {};
    let config = '';
    if (gateway.enabled !== false) {
      config = `[gateway]\nenabled = true\nallowed_destinations = ${toml(gateway.allow ?? [])}\n`;
      if (u.connect) config += `unix_connect = ${toml(u.connect)}\n`;
      if (u.listen) config += `unix_listen = ${toml(u.listen)}\n`;
      if (u.replaceStale) config += 'unix_replace_stale = true\n';
      if (u.maxListeners !== undefined) config += `unix_max_listeners = ${u.maxListeners}\n`;
      if (gateway.maxConnections) config += `max_connections = ${gateway.maxConnections}\n`;
      if (gateway.enableReverse) config += 'enable_reverse_tunnels = true\n';
    }
    const configPath = path.join(home, '.wsh', 'config.toml');
    fs.writeFileSync(configPath, config);
    const port = await freePort();
    const proc = spawn(SERVER_BIN, ['--port', String(port), '--generate-cert', '--config', configPath], {
      env: { PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config') }, stdio: ['ignore', 'pipe', 'pipe'],
    });
    procs.push(proc);
    let logs = '';
    await new Promise((resolve, reject) => {
      const onData = (d) => { logs += d; if (logs.includes('WebSocket TLS listener started')) resolve(); };
      proc.stdout.on('data', onData); proc.stderr.on('data', onData);
      proc.once('exit', (c) => reject(new Error(`wsh-server exited (${c}): ${logs}`)));
      setTimeout(() => reject(new Error(`wsh-server not ready: ${logs}`)), 10_000);
    });
    const client = new WshClient();
    await client.connect(`wss://127.0.0.1:${port}`, { username: 'tester', keyPair: kp });
    clients.push(client);
    const inbox = [];
    client.onGatewayMessage = (m) => inbox.push(m);
    return { client, inbox, proc, logs: () => logs };
  }

  /** A fake "docker daemon": HTTP over a unix socket. */
  async function fakeDaemon(sock) {
    const server = http.createServer((req, res) => {
      if (req.url === '/containers/json') { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify([{ Id: 'abc123', Names: ['/fake'] }])); return; }
      if (req.url === '/big') { const b = Buffer.alloc(20 * MiB); for (let i = 0; i < b.length; i += 4096) b.writeUInt32LE(i, i); res.end(b); return; }
      if (req.method === 'POST' && req.url === '/echo') { req.pipe(res); return; }
      res.statusCode = 404; res.end('nope');
    });
    await listenUnixSock(server, sock);
    closers.push(() => new Promise((r) => { server.closeAllConnections(); server.close(() => r()); }));
    return server;
  }
  const httpGet = (opts) => new Promise((resolve, reject) => {
    http.get({ ...opts, agent: false }, (res) => { const cs = []; res.on('data', (c) => cs.push(c)); res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(cs) })); }).on('error', reject);
  });

  describe('features', () => {
    it('advertises gateway-credit with the gateway and gateway-unix only when unix sockets are configured', async () => {
      const t = tmp();
      const a = await setup({ allow: [], unix: { connect: [`${t}/`] } });
      assert.ok(a.client.hasFeature('gateway-unix') && a.client.hasFeature('gateway-credit'));
      const b = await setup({ allow: ['*'] });
      assert.ok(b.client.hasFeature('gateway-credit'));
      assert.equal(b.client.hasFeature('gateway-unix'), false);
      await assert.rejects(b.client.openUnix(`${t}/x`), /gateway-unix/);
      const off = await setup({ enabled: false });
      assert.equal(off.client.hasFeature('gateway-credit'), false, 'no gateway, no gateway features');
      assert.equal(off.client.hasFeature('gateway-unix'), false);
    });
  });

  describe('OpenUnix', () => {
    it('reaches an HTTP server on a unix socket (request and response through the forward)', async () => {
      const t = tmp();
      await fakeDaemon(`${t}/d.sock`);
      const { client } = await setup({ allow: [], unix: { connect: [`${t}/d.sock`] } });
      const duplex = await client.openUnix(`${t}/d.sock`);
      const w = duplex.writable.getWriter();
      await w.write(new TextEncoder().encode('GET /containers/json HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n'));
      const text = (await readAll(duplex)).toString();
      assert.match(text, /^HTTP\/1\.1 200 OK/);
      assert.match(text, /"Id":"abc123"/);
    });

    it('forwardUnix: a TCP port and a local unix socket in front of the remote unix socket', async () => {
      const t = tmp();
      await fakeDaemon(`${t}/docker.sock`);
      const { client } = await setup({ allow: [], unix: { connect: [`${t}/docker.sock`] } });
      const tcp = await client.forwardUnix({ local: '127.0.0.1:0', remote: `${t}/docker.sock` });
      const r1 = await httpGet({ host: '127.0.0.1', port: tcp.address.port, path: '/containers/json' });
      assert.equal(JSON.parse(r1.body)[0].Id, 'abc123');
      const uds = await client.forwardUnix({ local: `${t}/local.sock`, remote: `${t}/docker.sock` });
      assert.equal(fs.statSync(`${t}/local.sock`).mode & 0o777, 0o600);
      assert.equal(JSON.parse((await httpGet({ socketPath: `${t}/local.sock`, path: '/containers/json' })).body)[0].Names[0], '/fake');
      await tcp.close(); await uds.close();
    });

    it('moves a large transfer both ways intact (20 MiB down, 12 MiB up)', async () => {
      const t = tmp();
      await fakeDaemon(`${t}/d.sock`);
      const { client } = await setup({ allow: [], unix: { connect: [`${t}/d.sock`] } });
      const fwd = await client.forwardUnix({ local: '127.0.0.1:0', remote: `${t}/d.sock` });
      const down = await httpGet({ host: '127.0.0.1', port: fwd.address.port, path: '/big' });
      const expected = Buffer.alloc(20 * MiB); for (let i = 0; i < expected.length; i += 4096) expected.writeUInt32LE(i, i);
      assert.equal(down.body.length, 20 * MiB);
      assert.equal(sha(down.body), sha(expected));
      const payload = crypto.randomBytes(12 * MiB);
      const up = await new Promise((resolve, reject) => {
        const req = http.request({ host: '127.0.0.1', port: fwd.address.port, path: '/echo', method: 'POST', agent: false }, (res) => { const cs = []; res.on('data', (c) => cs.push(c)); res.on('end', () => resolve(Buffer.concat(cs))); });
        req.on('error', reject); req.end(payload);
      });
      assert.equal(sha(up), sha(payload));
      await fwd.close();
    });

    it('serves many concurrent connections and enforces max_connections', async () => {
      const t = tmp();
      const echo = net.createServer((s) => { s.on('data', (d) => s.write(d)); s.on('error', () => {}); });
      await listenUnixSock(echo, `${t}/e.sock`); closers.push(() => new Promise((r) => echo.close(r)));
      const { client } = await setup({ allow: [], unix: { connect: [`${t}/e.sock`] }, maxConnections: 24 });
      const results = await Promise.all(Array.from({ length: 24 }, async (_, i) => {
        const d = await client.openUnix(`${t}/e.sock`);
        const w = d.writable.getWriter();
        const msg = crypto.randomBytes(100_000 + i);
        const reader = d.readable.getReader();
        const writing = w.write(msg);
        let got = 0; const chunks = [];
        while (got < msg.length) { const { value, done } = await reader.read(); if (done) break; chunks.push(value); got += value.length; }
        await writing;
        const same = Buffer.concat(chunks).equals(msg);
        if (i < 23) d.destroy(); // one stays open: the cap below counts it
        return same;
      }));
      assert.deepEqual(results, new Array(24).fill(true));
    });

    it('refuses with GatewayFail 7 beyond the connection limit', async () => {
      const t = tmp();
      const idle = net.createServer((s) => { s.on('error', () => {}); });
      await listenUnixSock(idle, `${t}/i.sock`); closers.push(() => new Promise((r) => idle.close(r)));
      const { client } = await setup({ allow: [], unix: { connect: [`${t}/i.sock`] }, maxConnections: 2 });
      await client.openUnix(`${t}/i.sock`); await client.openUnix(`${t}/i.sock`);
      await assert.rejects(client.openUnix(`${t}/i.sock`), (e) => e instanceof GatewayError && e.code === 7);
    });

    describe('policy (default deny; checked after realpath of the parent; no symlink escape)', () => {
      const denied = (client, p) => assert.rejects(client.openUnix(p), (e) => e instanceof GatewayError && e.code === 4, `${p} should be refused by policy`);

      it('refuses everything without a unix policy, and an empty one', async () => {
        const t = tmp();
        const echo = net.createServer(); await listenUnixSock(echo, `${t}/e.sock`); closers.push(() => new Promise((r) => echo.close(r)));
        const a = await setup({ allow: ['*'] });
        await a.client.sendControl({ type: MSG.OPEN_UNIX, gateway_id: 9, path: `${t}/e.sock` });
        assert.equal((await until(() => a.inbox.find((m) => m.type === MSG.GATEWAY_FAIL), 'fail')).code, 4);
        const b = await setup({ allow: [], unix: { connect: [] } });
        await b.client.sendControl({ type: MSG.OPEN_UNIX, gateway_id: 9, path: `${t}/e.sock` });
        assert.equal((await until(() => b.inbox.find((m) => m.type === MSG.GATEWAY_FAIL), 'fail')).code, 4);
      });

      it('refuses paths outside the list, relative paths, "..", directories, and a file that is not a socket', async () => {
        const t = tmp();
        fs.mkdirSync(`${t}/ok`); fs.mkdirSync(`${t}/other`);
        const inside = net.createServer(); await listenUnixSock(inside, `${t}/ok/s.sock`); closers.push(() => new Promise((r) => inside.close(r)));
        const outside = net.createServer(); await listenUnixSock(outside, `${t}/other/s.sock`); closers.push(() => new Promise((r) => outside.close(r)));
        fs.writeFileSync(`${t}/ok/plain`, 'x');
        const { client, inbox } = await setup({ allow: [], unix: { connect: [`${t}/ok/`] } });
        const d = await client.openUnix(`${t}/ok/s.sock`); d.destroy();
        await denied(client, `${t}/other/s.sock`);
        await denied(client, 's.sock');
        await denied(client, `${t}/ok/../other/s.sock`);
        await denied(client, `${t}/ok`);
        await denied(client, `${t}/ok/plain`);
        await denied(client, `${t}/ok/s.sock\0/etc`);
        await client.sendControl({ type: MSG.OPEN_UNIX, gateway_id: 77, path: '' });
        assert.equal((await until(() => inbox.find((m) => m.type === MSG.GATEWAY_FAIL && m.gateway_id === 77), 'fail 77')).code, 4);
      });

      it('refuses a symlink that leaves the allowed directory (the file, or a directory in the path)', async () => {
        const t = tmp();
        fs.mkdirSync(`${t}/ok`); fs.mkdirSync(`${t}/other`);
        const outside = net.createServer(); await listenUnixSock(outside, `${t}/other/s.sock`); closers.push(() => new Promise((r) => outside.close(r)));
        fs.symlinkSync(`${t}/other/s.sock`, `${t}/ok/link.sock`);
        fs.symlinkSync(`${t}/other`, `${t}/ok/dirlink`);
        const { client } = await setup({ allow: [], unix: { connect: [`${t}/ok/`] } });
        await denied(client, `${t}/ok/link.sock`);
        await denied(client, `${t}/ok/dirlink/s.sock`);
      });

      it('matches an exact path only exactly, and resolves the allowed path the same way', async () => {
        const t = tmp();
        fs.mkdirSync(`${t}/real`);
        fs.symlinkSync(`${t}/real`, `${t}/alias`);
        for (const n of ['a.sock', 'b.sock']) { const s = net.createServer(); await listenUnixSock(s, `${t}/real/${n}`); closers.push(() => new Promise((r) => s.close(r))); }
        const { client } = await setup({ allow: [], unix: { connect: [`${t}/alias/a.sock`] } });
        (await client.openUnix(`${t}/real/a.sock`)).destroy();
        (await client.openUnix(`${t}/alias/a.sock`)).destroy();
        await denied(client, `${t}/real/b.sock`);
      });

      it('refuses the abstract namespace unless listed', async () => {
        const t = tmp();
        const { client } = await setup({ allow: [], unix: { connect: [`${t}/`] } });
        await denied(client, '@anything');
        await denied(client, '\0anything');
      });

      it('refuses to start with a pattern that would allow everything', async () => {
        const t = tmp();
        for (const bad of ['/', '@', 'relative.sock', `${t}/../x/`]) {
          const home = fs.mkdtempSync(path.join(os.tmpdir(), 'wsh-fw-bad-')); dirs.push(home);
          fs.mkdirSync(path.join(home, '.wsh'));
          fs.writeFileSync(path.join(home, '.wsh', 'config.toml'), `[gateway]\nenabled = true\nunix_connect = ${toml([bad])}\n`);
          let out = '';
          const code = await new Promise((resolve) => {
            const p = spawn(SERVER_BIN, ['--port', String(9), '--generate-cert', '--config', path.join(home, '.wsh', 'config.toml')], { env: { PATH: process.env.PATH, HOME: home }, stdio: ['ignore', 'pipe', 'pipe'] });
            p.stdout.on('data', (d) => { out += d; }); p.stderr.on('data', (d) => { out += d; });
            p.on('exit', resolve);
            setTimeout(() => { p.kill(); resolve('still running'); }, 5000);
          });
          assert.notEqual(code, 'still running', `${bad}: ${out}`);
          assert.notEqual(code, 0);
          assert.match(out, /unix_connect/);
        }
      });
    });
  });

  describe('ListenUnix (the host listens)', () => {
    it('the host creates a private socket, hands each connection to the client, and unlinks it on close', async () => {
      const t = tmp();
      const { client } = await setup({ allow: [], unix: { listen: [`${t}/`] } });
      const seen = [];
      const handle = await client.listenUnix(`${t}/r.sock`, {
        onConnection: async (duplex) => {
          seen.push(duplex);
          const reader = duplex.readable.getReader(); const w = duplex.writable.getWriter();
          for (;;) { const { value, done } = await reader.read(); if (done) break; await w.write(new TextEncoder().encode(`echo:${Buffer.from(value)}`)); }
          await w.close();
        },
      });
      assert.equal(fs.statSync(`${t}/r.sock`).isSocket(), true);
      assert.equal(fs.statSync(`${t}/r.sock`).mode & 0o777, 0o600, 'mode 0600');
      const answers = await Promise.all([1, 2, 3].map((n) => new Promise((resolve, reject) => {
        const s = net.connect(`${t}/r.sock`); const cs = [];
        s.on('connect', () => s.write(`hi${n}`)); s.on('data', (d) => { cs.push(d); s.end(); }); s.on('close', () => resolve(Buffer.concat(cs).toString())); s.on('error', reject);
      })));
      assert.deepEqual(answers.sort(), ['echo:hi1', 'echo:hi2', 'echo:hi3']);
      assert.equal(seen.length, 3);
      await handle.close();
      await until(() => !exists(`${t}/r.sock`), 'socket file removed on close');
    });

    it('forwardUnix reverse: -R /remote.sock:127.0.0.1:PORT', async () => {
      const t = tmp();
      const svc = net.createServer((s) => { s.on('data', (d) => s.write(Buffer.concat([Buffer.from('svc:'), d]))); s.on('error', () => {}); });
      const svcPort = await listenTcp(svc); closers.push(() => new Promise((r) => svc.close(r)));
      const { client } = await setup({ allow: [], unix: { listen: [`${t}/`] } });
      const fwd = await client.forwardUnix({ reverse: true, remote: `${t}/rev.sock`, local: `127.0.0.1:${svcPort}` });
      const answer = await new Promise((resolve, reject) => {
        const s = net.connect(`${t}/rev.sock`); s.on('connect', () => s.write('ping')); s.on('data', (d) => { resolve(d.toString()); s.destroy(); }); s.on('error', reject);
      });
      assert.equal(answer, 'svc:ping');
      await fwd.close();
      await until(() => !exists(`${t}/rev.sock`), 'socket removed');
    });

    it('removes the socket and closes its connections when the client disconnects', async () => {
      const t = tmp();
      const { client } = await setup({ allow: [], unix: { listen: [`${t}/`] } });
      await client.listenUnix(`${t}/gone.sock`, { onConnection: () => {} });
      const peer = net.connect(`${t}/gone.sock`); peer.on('error', () => {});
      await until(() => new Promise((r) => peer.once('connect', () => r(true))), 'connect');
      const closed = new Promise((r) => peer.once('close', r));
      await client.disconnect();
      await until(() => !exists(`${t}/gone.sock`), 'socket file removed on disconnect');
      await Promise.race([closed, sleep(3000).then(() => assert.fail('the accepted connection stayed open'))]);
    });

    it('refuses listening outside the list, on a connect-only path, and when unix listening is off; counts listeners', async () => {
      const t = tmp();
      fs.mkdirSync(`${t}/ok`); fs.mkdirSync(`${t}/no`);
      const { client } = await setup({ allow: [], unix: { listen: [`${t}/ok/`], connect: [`${t}/no/`], maxListeners: 1 } });
      const refused = (p, re) => assert.rejects(client.listenUnix(p, { onConnection() {} }), (e) => e instanceof GatewayError && re.test(e.message));
      await refused(`${t}/no/s.sock`, /not allowed/);
      await refused(`${t}/ok/../no/s.sock`, /absolute|malformed/);
      assert.equal(exists(`${t}/no/s.sock`), false);
      await client.listenUnix(`${t}/ok/one.sock`, { onConnection() {} });
      await refused(`${t}/ok/two.sock`, /too many/);
      const off = await setup({ allow: ['*'], unix: { connect: [`${t}/`] } });
      await assert.rejects(off.client.listenUnix(`${t}/ok/x.sock`, { onConnection() {} }), /not enabled/);
    });

    describe('stale sockets', () => {
      /** Leave a socket file behind with nothing listening: a child that listens and is SIGKILLed. */
      async function staleSocket(p) {
        const child = spawn(process.execPath, ['-e', `require('node:net').createServer().listen(process.argv[1], () => process.kill(process.pid, 'SIGKILL'))`, p], { stdio: 'ignore' });
        await new Promise((r) => child.on('exit', r));
        assert.equal(fs.lstatSync(p).isSocket(), true);
      }
      const attempt = (client, p, replace) => client.listenUnix(p, { replace, onConnection() {} });

      it('is not replaced unless the request says so AND policy allows it', async () => {
        const t = tmp();
        await staleSocket(`${t}/s.sock`);
        const strict = await setup({ allow: [], unix: { listen: [`${t}/`] } });
        await assert.rejects(attempt(strict.client, `${t}/s.sock`), /address in use/);
        await assert.rejects(attempt(strict.client, `${t}/s.sock`, true), /not allowed by the gateway policy/);
        const lax = await setup({ allow: [], unix: { listen: [`${t}/`], replaceStale: true } });
        await assert.rejects(attempt(lax.client, `${t}/s.sock`), /address in use/, 'policy allows it but the request did not ask');
        assert.equal(exists(`${t}/s.sock`), true, 'still there');
        const h = await attempt(lax.client, `${t}/s.sock`, true);
        const reachable = await new Promise((resolve) => { const s = net.connect(`${t}/s.sock`); s.on('connect', () => { s.destroy(); resolve(true); }); s.on('error', () => resolve(false)); });
        assert.equal(reachable, true, 'the host listens on the replaced path');
        await h.close();
      });

      it('never replaces a live socket, or a file that is not a socket', async () => {
        const t = tmp();
        const live = net.createServer(); await listenUnixSock(live, `${t}/live.sock`); closers.push(() => new Promise((r) => live.close(r)));
        fs.writeFileSync(`${t}/file`, 'precious');
        const { client } = await setup({ allow: [], unix: { listen: [`${t}/`], replaceStale: true } });
        await assert.rejects(attempt(client, `${t}/live.sock`, true), /live/);
        await assert.rejects(attempt(client, `${t}/file`, true), /not a socket/);
        assert.equal(fs.readFileSync(`${t}/file`, 'utf8'), 'precious');
      });
    });
  });

  describe('GatewayCredit', () => {
    const rss = (pid) => Number(execFileSync('ps', ['-o', 'rss=', '-p', String(pid)], { encoding: 'utf8' }).trim()) / 1024;

    it('a fast origin and a stalled client: the server stops at the credit and its memory stays flat', async () => {
      const t = tmp();
      // An origin that writes as fast as the peer lets it, forever.
      const firehose = net.createServer((s) => {
        const chunk = Buffer.alloc(64 * 1024, 0x5a);
        let open = true;
        s.on('error', () => { open = false; }); s.on('close', () => { open = false; });
        const pump = () => { while (open && s.write(chunk)); if (open) s.once('drain', pump); };
        pump();
      });
      await listenUnixSock(firehose, `${t}/fire.sock`); closers.push(() => new Promise((r) => { firehose.close(r); }));
      const { client, proc } = await setup({ allow: [], unix: { connect: [`${t}/fire.sock`] } });
      const duplex = await client.openUnix(`${t}/fire.sock`); // never read: no credit comes back
      await sleep(500);
      const before = rss(proc.pid);
      await sleep(3000);
      const growth = rss(proc.pid) - before;
      assert.ok(growth < 16, `the server's memory grew by ${growth.toFixed(1)} MiB while the client was stalled`);
      // Reading resumes the flow.
      const reader = duplex.readable.getReader();
      let got = 0;
      while (got < 2 * MiB) { const { value, done } = await reader.read(); if (done) break; got += value.length; }
      assert.ok(got >= 2 * MiB, 'reading brings the data (and the credit) back');
      duplex.destroy();
    });

    it('a slow origin and a fast client: the client\'s writes are held by credit and the transfer completes intact', async () => {
      const t = tmp();
      // An origin that takes data slowly and echoes its length at the end.
      const slow = net.createServer((s) => {
        let n = 0; const h = crypto.createHash('sha256');
        s.on('data', (d) => { n += d.length; h.update(d); s.pause(); setTimeout(() => s.resume(), 5); });
        s.on('end', () => { s.end(`${n}:${h.digest('hex')}`); });
        s.on('error', () => {});
      });
      await listenUnixSock(slow, `${t}/slow.sock`); closers.push(() => new Promise((r) => slow.close(r)));
      const { client } = await setup({ allow: [], unix: { connect: [`${t}/slow.sock`] } });
      const duplex = await client.openUnix(`${t}/slow.sock`);
      const payload = crypto.randomBytes(3 * MiB);
      const w = duplex.writable.getWriter();
      const t0 = Date.now();
      await w.write(payload);
      await w.close();
      assert.equal((await readAll(duplex)).toString(), `${payload.length}:${sha(payload)}`);
      assert.ok(Date.now() - t0 > 200, 'a slow origin slows the writer (the credit held it back)');
    });

    it('closes a connection whose client sends past the credit it was given (raw frames)', async () => {
      const t = tmp();
      const socks = new Set();
      const mute = net.createServer((s) => { socks.add(s); s.pause(); s.on('error', () => {}); });
      await listenUnixSock(mute, `${t}/mute.sock`); closers.push(() => new Promise((r) => { mute.close(r); for (const s of socks) s.destroy(); }));
      const { client, inbox } = await setup({ allow: [], unix: { connect: [`${t}/mute.sock`] } });
      await client.sendControl({ type: MSG.OPEN_UNIX, gateway_id: 5, path: `${t}/mute.sock` });
      await until(() => inbox.find((m) => m.type === MSG.GATEWAY_OK && m.gateway_id === 5), 'ok');
      // 5 x 60 KiB against 256 KiB of credit, to an origin that takes nothing.
      for (let i = 0; i < 5; i++) await client.sendControl({ type: MSG.GATEWAY_DATA, gateway_id: 5, data: new Uint8Array(60 * 1024) });
      const closed = await until(() => inbox.find((m) => m.type === MSG.GATEWAY_CLOSE && m.gateway_id === 5), 'close for the overrun');
      assert.match(closed.reason ?? '', /credit/);
    });
  });
});
