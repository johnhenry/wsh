// test/gateway-unix.test.mjs -- #120: unix-domain socket forwarding (streamlocal) through the Node host, both
// directions, with the host's path policy. Real sockets in a temp dir; nothing touches a real daemon: the
// "Docker API" below is a fake HTTP server on a unix socket.
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { MSG } from '@johnhenry/wsh';
import { GatewayError } from '../src/gateway-client.mjs';
import { fixture, until, sleep, listen } from './gateway-fixture.mjs';

const MiB = 1024 * 1024;
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const listenUnix = (server, p) => new Promise((resolve, reject) => { server.once('error', reject); server.listen(p, () => resolve()); });
const exists = (p) => fs.existsSync(p);

/** Read a duplex to its end. */
async function readAll(duplex) {
  const chunks = [];
  const reader = duplex.readable.getReader();
  for (;;) { const { value, done } = await reader.read(); if (done) break; chunks.push(value); }
  return Buffer.concat(chunks);
}

describe('unix-domain socket forwarding', () => {
  const fx = fixture();
  let dir;
  const tmp = () => { dir ??= fs.mkdtempSync(path.join(os.tmpdir(), 'wsh-u-')); return fs.realpathSync(dir); };
  afterEach(async () => {
    await fx.teardown();
    if (dir) { fs.rmSync(dir, { recursive: true, force: true }); dir = undefined; } // a directory this test made
  });

  /** A fake "docker daemon": HTTP over a unix socket. */
  async function fakeDaemon(sock) {
    const server = http.createServer((req, res) => {
      if (req.url === '/containers/json') { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify([{ Id: 'abc123', Names: ['/fake'] }])); return; }
      if (req.url === '/big') { const b = Buffer.alloc(20 * MiB); for (let i = 0; i < b.length; i += 4096) b.writeUInt32LE(i, i); res.end(b); return; }
      if (req.method === 'POST' && req.url === '/echo') { req.pipe(res); return; }
      res.statusCode = 404; res.end('nope');
    });
    await listenUnix(server, sock);
    fx.cleanups.push(() => new Promise((r) => { server.closeAllConnections(); server.close(() => r()); }));
    return server;
  }
  const httpGet = (opts) => new Promise((resolve, reject) => {
    http.get({ ...opts, agent: false }, (res) => { const cs = []; res.on('data', (c) => cs.push(c)); res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(cs) })); }).on('error', reject);
  });

  it('advertises gateway-unix only when unix is configured', async () => {
    const t = tmp();
    const a = await fx.setup({ allow: [], unix: { connect: [`${t}/`] } });
    assert.ok(a.client.hasFeature('gateway-unix') && a.client.hasFeature('gateway-credit'));
    const b = await fx.setup({ allow: ['*'] });
    assert.equal(b.client.hasFeature('gateway-unix'), false);
    await assert.rejects(b.client.openUnix(`${t}/x`), /gateway-unix/);
  });

  it('openUnix reaches an HTTP server on a unix socket (request and response through the forward)', async () => {
    const t = tmp();
    await fakeDaemon(`${t}/d.sock`);
    const { client } = await fx.setup({ allow: [], unix: { connect: [`${t}/d.sock`] } });
    const duplex = await client.openUnix(`${t}/d.sock`);
    const w = duplex.writable.getWriter();
    await w.write(new TextEncoder().encode('GET /containers/json HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n'));
    const text = (await readAll(duplex)).toString();
    assert.match(text, /^HTTP\/1\.1 200 OK/);
    assert.match(text, /"Id":"abc123"/);
  });

  it('forwardUnix: -L 127.0.0.1:PORT:/remote.sock style (a TCP port in front of the remote unix socket), and unix-to-unix', async () => {
    const t = tmp();
    await fakeDaemon(`${t}/docker.sock`);
    const { client } = await fx.setup({ allow: [], unix: { connect: [`${t}/docker.sock`] } });
    const tcp = await client.forwardUnix({ local: '127.0.0.1:0', remote: `${t}/docker.sock` });
    const r1 = await httpGet({ host: '127.0.0.1', port: tcp.address.port, path: '/containers/json' });
    assert.equal(r1.status, 200);
    assert.equal(JSON.parse(r1.body)[0].Id, 'abc123');
    const uds = await client.forwardUnix({ local: `${t}/local.sock`, remote: `${t}/docker.sock` });
    assert.equal(fs.statSync(`${t}/local.sock`).mode & 0o777, 0o600, 'the local socket is private');
    const r2 = await httpGet({ socketPath: `${t}/local.sock`, path: '/containers/json' });
    assert.equal(JSON.parse(r2.body)[0].Names[0], '/fake');
    assert.equal((await httpGet({ socketPath: `${t}/local.sock`, path: '/missing' })).status, 404);
    await tcp.close();
    await uds.close();
    assert.equal(exists(`${t}/local.sock`), false, 'closing the forward removes the local socket');
  });

  it('moves a large transfer both ways intact', async () => {
    const t = tmp();
    await fakeDaemon(`${t}/d.sock`);
    const { client } = await fx.setup({ allow: [], unix: { connect: [`${t}/d.sock`] } });
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

  it('serves many concurrent connections', async () => {
    const t = tmp();
    const echo = net.createServer((s) => { s.on('data', (d) => s.write(d)); s.on('error', () => {}); });
    await listenUnix(echo, `${t}/e.sock`); fx.nets.push(echo);
    const { client } = await fx.setup({ allow: [], unix: { connect: [`${t}/e.sock`] }, maxConnections: 32 });
    const results = await Promise.all(Array.from({ length: 24 }, async (_, i) => {
      const d = await client.openUnix(`${t}/e.sock`);
      const w = d.writable.getWriter();
      const msg = crypto.randomBytes(100_000 + i);
      const reader = d.readable.getReader();
      const writing = w.write(msg);
      let got = 0; const chunks = [];
      while (got < msg.length) { const { value, done } = await reader.read(); if (done) break; chunks.push(value); got += value.length; }
      await writing;
      d.destroy();
      return Buffer.concat(chunks).equals(msg);
    }));
    assert.deepEqual(results, new Array(24).fill(true));
  });

  it('enforces maxConnections for unix connections', async () => {
    const t = tmp();
    const idle = net.createServer((s) => { s.on('error', () => {}); }); await listenUnix(idle, `${t}/i.sock`); fx.nets.push(idle);
    const { client } = await fx.setup({ allow: [], unix: { connect: [`${t}/i.sock`] }, maxConnections: 2 });
    await client.openUnix(`${t}/i.sock`); await client.openUnix(`${t}/i.sock`);
    await assert.rejects(client.openUnix(`${t}/i.sock`), (e) => e instanceof GatewayError && e.code === 7);
  });

  describe('policy (default deny; checked after realpath of the parent; no symlink escape)', () => {
    const denied = async (client, p) => {
      await assert.rejects(client.openUnix(p), (e) => e instanceof GatewayError && e.code === 4, `${p} should be refused by policy`);
    };

    it('refuses everything without a unix policy, and an empty one', async () => {
      const t = tmp();
      const echo = net.createServer(); await listenUnix(echo, `${t}/e.sock`); fx.nets.push(echo);
      const a = await fx.setup({ allow: ['*'] });
      a.inbox.length = 0;
      await a.client.sendControl({ type: MSG.OPEN_UNIX, gateway_id: 9, path: `${t}/e.sock` });
      assert.equal((await until(() => a.inbox.find((m) => m.type === MSG.GATEWAY_FAIL), 'fail')).code, 4);
      const b = await fx.setup({ allow: [], unix: { connect: [] } });
      await b.client.sendControl({ type: MSG.OPEN_UNIX, gateway_id: 9, path: `${t}/e.sock` });
      assert.equal((await until(() => b.inbox.find((m) => m.type === MSG.GATEWAY_FAIL), 'fail')).code, 4);
    });

    it('refuses paths outside the list, relative paths, "..", directories, and a file that is not a socket', async () => {
      const t = tmp();
      fs.mkdirSync(`${t}/ok`); fs.mkdirSync(`${t}/other`);
      const inside = net.createServer(); await listenUnix(inside, `${t}/ok/s.sock`); fx.nets.push(inside);
      const outside = net.createServer(); await listenUnix(outside, `${t}/other/s.sock`); fx.nets.push(outside);
      fs.writeFileSync(`${t}/ok/plain`, 'x');
      const { client, inbox } = await fx.setup({ allow: [], unix: { connect: [`${t}/ok/`] } });
      const d = await client.openUnix(`${t}/ok/s.sock`); d.destroy();
      await denied(client, `${t}/other/s.sock`);
      await denied(client, 's.sock');
      await denied(client, `${t}/ok/../other/s.sock`);
      await denied(client, `${t}/ok`);
      await denied(client, `${t}/ok/plain`); // allowed place, but not a socket
      await denied(client, `${t}/ok/s.sock\0/etc`);
      await assert.rejects(client.openUnix(''), TypeError); // the client API refuses an empty path itself...
      await client.sendControl({ type: MSG.OPEN_UNIX, gateway_id: 77, path: '' }); // ...and the host does too
      assert.equal((await until(() => inbox.find((m) => m.type === MSG.GATEWAY_FAIL && m.gateway_id === 77), 'fail 77')).code, 4);
    });

    it('refuses a symlink that leaves the allowed directory (the file, or a directory in the path)', async () => {
      const t = tmp();
      fs.mkdirSync(`${t}/ok`); fs.mkdirSync(`${t}/other`);
      const outside = net.createServer(); await listenUnix(outside, `${t}/other/s.sock`); fx.nets.push(outside);
      fs.symlinkSync(`${t}/other/s.sock`, `${t}/ok/link.sock`);
      fs.symlinkSync(`${t}/other`, `${t}/ok/dirlink`);
      const { client } = await fx.setup({ allow: [], unix: { connect: [`${t}/ok/`] } });
      await denied(client, `${t}/ok/link.sock`);
      await denied(client, `${t}/ok/dirlink/s.sock`);
    });

    it('matches an exact path only exactly, and resolves the allowed path the same way (an allowed alias of the directory works)', async () => {
      const t = tmp();
      fs.mkdirSync(`${t}/real`);
      fs.symlinkSync(`${t}/real`, `${t}/alias`);
      for (const n of ['a.sock', 'b.sock']) { const s = net.createServer(); await listenUnix(s, `${t}/real/${n}`); fx.nets.push(s); }
      const { client } = await fx.setup({ allow: [], unix: { connect: [`${t}/alias/a.sock`] } });
      (await client.openUnix(`${t}/real/a.sock`)).destroy(); // same file through either spelling
      (await client.openUnix(`${t}/alias/a.sock`)).destroy();
      await denied(client, `${t}/real/b.sock`);
    });

    it('refuses the abstract namespace unless listed, and refuses patterns that would allow everything', async () => {
      const t = tmp();
      const { client } = await fx.setup({ allow: [], unix: { connect: [`${t}/`] } });
      await denied(client, '@anything');
      await denied(client, '\0anything');
      const listed = await fx.setup({ allow: [], unix: { connect: ['@wsh-test/'] } });
      await assert.rejects(listed.client.openUnix('@other'), (e) => e.code === 4);
      await assert.rejects(listed.client.openUnix('@wsh-test/x'), (e) => e instanceof GatewayError && e.code !== 4, 'passes policy (it is listed); there is simply nothing listening');
      const { createWshServer } = await import('@johnhenry/wsh/server');
      for (const bad of ['/', '@', 'relative.sock', `${t}/../x/`]) assert.throws(() => createWshServer({ gateway: { allow: [], unix: { connect: [bad] } } }), /gateway\.unix/);
    });
  });

  describe('listening on the host (the other direction)', () => {
    it('ListenUnix: the host creates a private socket, hands each connection to the client, and unlinks it on close', async () => {
      const t = tmp();
      const { client } = await fx.setup({ allow: [], unix: { listen: [`${t}/`] } });
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

    it('ListenUnix: closing removes only the socket the host made: a file or socket put at the path since survives, and the private directory is gone', async () => {
      const t = tmp();
      const { client } = await fx.setup({ allow: [], unix: { listen: [`${t}/`] } });
      const listen = (name) => client.listenUnix(`${t}/${name}`, { onConnection: () => {} });
      // Nothing else is left behind by an ordinary listener.
      const plain = await listen('p.sock');
      assert.equal(fs.lstatSync(`${t}/p.sock`).isSocket(), true, 'the name is a socket, not a link');
      await plain.close();
      await until(() => fs.readdirSync(t).length === 0, 'the socket and its private directory removed');

      // A regular file put at the path while the listener is up.
      const a = await listen('a.sock');
      fs.unlinkSync(`${t}/a.sock`); fs.writeFileSync(`${t}/a.sock`, 'not the host\'s');
      await a.close();
      await until(() => fs.readdirSync(t).join() === 'a.sock', 'only the stranger\'s file left');
      assert.equal(fs.readFileSync(`${t}/a.sock`, 'utf8'), 'not the host\'s');

      // Another listening socket put at the path.
      const b = await listen('b.sock');
      fs.unlinkSync(`${t}/b.sock`);
      const other = net.createServer((s) => { s.on('error', () => {}); s.end('other'); }); fx.nets.push(other);
      await listenUnix(other, `${t}/b.sock`);
      await b.close();
      await until(() => fs.readdirSync(t).join() === 'a.sock,b.sock', 'only the strangers\' files left');
      const said = await new Promise((resolve, reject) => { const s = net.connect(`${t}/b.sock`); const cs = []; s.on('data', (d) => cs.push(d)); s.on('close', () => resolve(Buffer.concat(cs).toString())); s.on('error', reject); });
      assert.equal(said, 'other');
    });

    it('forwardUnix reverse: -R /remote.sock:127.0.0.1:PORT (the host listens, connections are made to a local TCP service)', async () => {
      const t = tmp();
      const svc = net.createServer((s) => { s.on('data', (d) => s.write(Buffer.concat([Buffer.from('svc:'), d]))); s.on('error', () => {}); });
      const svcPort = await listen(svc); fx.nets.push(svc);
      const { client } = await fx.setup({ allow: [], unix: { listen: [`${t}/`] } });
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
      const { client } = await fx.setup({ allow: [], unix: { listen: [`${t}/`] } });
      await client.listenUnix(`${t}/gone.sock`, { onConnection: () => {} });
      const peer = net.connect(`${t}/gone.sock`); peer.on('error', () => {});
      await until(() => new Promise((r) => peer.once('connect', () => r(true))), 'connect');
      const closed = new Promise((r) => peer.once('close', r));
      await client.disconnect();
      await until(() => !exists(`${t}/gone.sock`), 'socket file removed on disconnect');
      await Promise.race([closed, sleep(3000).then(() => assert.fail('the accepted connection stayed open'))]);
    });

    it('refuses listening outside the list, on a connect-only path, and when unix is off; counts listeners', async () => {
      const t = tmp();
      fs.mkdirSync(`${t}/ok`); fs.mkdirSync(`${t}/no`);
      const { client } = await fx.setup({ allow: [], unix: { listen: [`${t}/ok/`], connect: [`${t}/no/`], maxListeners: 1 } });
      const refused = (p, re) => assert.rejects(client.listenUnix(p, { onConnection() {} }), (e) => e instanceof GatewayError && re.test(e.message));
      await refused(`${t}/no/s.sock`, /not allowed/);
      await refused(`${t}/ok/../no/s.sock`, /absolute|malformed/);
      assert.equal(exists(`${t}/no/s.sock`), false);
      await client.listenUnix(`${t}/ok/one.sock`, { onConnection() {} });
      await refused(`${t}/ok/two.sock`, /too many/);
      const off = await fx.setup({ allow: ['*'], unix: { connect: [`${t}/`] } });
      await assert.rejects(off.client.listenUnix(`${t}/ok/x.sock`, { onConnection() {} }), /not enabled/);
    });

    describe('stale sockets (the StreamLocalBindUnlink question: default no)', () => {
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
        const strict = await fx.setup({ allow: [], unix: { listen: [`${t}/`] } });
        await assert.rejects(attempt(strict.client, `${t}/s.sock`), /address in use/);
        await assert.rejects(attempt(strict.client, `${t}/s.sock`, true), /not allowed by the gateway policy/);
        const lax = await fx.setup({ allow: [], unix: { listen: [`${t}/`], replaceStale: true } });
        await assert.rejects(attempt(lax.client, `${t}/s.sock`), /address in use/, 'policy allows it but the request did not ask');
        assert.equal(exists(`${t}/s.sock`), true, 'still there');
        const h = await attempt(lax.client, `${t}/s.sock`, true);
        const echoed = await new Promise((resolve) => { const s = net.connect(`${t}/s.sock`); s.on('connect', () => { s.destroy(); resolve(true); }); s.on('error', () => resolve(false)); });
        assert.equal(echoed, true, 'the host listens on the replaced path');
        await h.close();
      });

      it('never replaces a live socket, or a file that is not a socket', async () => {
        const t = tmp();
        const live = net.createServer(); await listenUnix(live, `${t}/live.sock`); fx.nets.push(live);
        fs.writeFileSync(`${t}/file`, 'precious');
        const { client } = await fx.setup({ allow: [], unix: { listen: [`${t}/`], replaceStale: true } });
        await assert.rejects(attempt(client, `${t}/live.sock`, true), /live/);
        await assert.rejects(attempt(client, `${t}/file`, true), /not a socket/);
        assert.equal(fs.readFileSync(`${t}/file`, 'utf8'), 'precious');
      });
    });
  });
});
