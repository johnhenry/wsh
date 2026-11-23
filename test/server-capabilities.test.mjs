// test/server-capabilities.test.mjs -- per-key capabilities on the Node host (wsh #122, step two): `capabilities="..."` and
// `expires="..."` in an authorized_keys line, and an `authorize()` that returns a capability set. Every entry the host has gets a
// refusal test (a key without the capability is refused, naming it) and a served test (a key with it is served). The grammar and
// the allow/refuse table are in test/key-options.test.mjs (shared vectors, also run by the Rust server).
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { createWshServer } from '@johnhenry/wsh/server';
import { WshClient, generateKeyPair, exportPublicKeySSH, resolveDns as resolveDnsMsg, openUdp as openUdpMsg } from '@johnhenry/wsh';
import { REFUSAL_REASONS } from '@johnhenry/wsh/host';

const dec = new TextDecoder();
const until = async (fn, what, ms = 4000) => {
  const t = Date.now();
  while (!(await fn())) { if (Date.now() - t > ms) throw new Error(`timed out waiting for ${what}`); await new Promise((r) => setTimeout(r, 10)); }
};
const listen = (server) => new Promise((r) => server.listen(0, '127.0.0.1', () => r(server.address().port)));

describe('per-key capabilities on the Node host (#122, step two)', () => {
  const keys = {}; const clients = []; const refused = []; const logs = []; const execCalls = [];
  let server; let url; let root; let sockDir; let echoPort; let echo; let unixServer;

  const past = '2020-01-01T00:00:00Z';
  const future = '2999-01-01T00:00:00Z';

  before(async () => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'wsh-caps-'));
    fs.writeFileSync(path.join(root, 'hello.txt'), 'hello');
    sockDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'wsh-capsock-')));
    echo = net.createServer((c) => { c.on('data', (d) => c.write(Buffer.concat([Buffer.from('echo:'), d]))); c.on('error', () => {}); });
    echoPort = await listen(echo);
    unixServer = net.createServer((c) => { c.on('data', (d) => c.write(Buffer.concat([Buffer.from('unix:'), d]))); c.on('error', () => {}); });
    await new Promise((r) => unixServer.listen(path.join(sockDir, 'ok.sock'), r));

    const caps = {
      exec: 'exec',
      pty: 'pty',
      fsRead: 'fs:read',
      fsWrite: 'fs:write',
      fsBoth: 'fs:read,fs:write',
      mcpEcho: 'mcp:echo',
      mcpAll: 'mcp:*',
      relay: 'relay',
      nothing: '',
      gateway: `gateway:tcp:127.0.0.1:${echoPort},gateway:listen:tcp:*,unix:${sockDir}/ok.sock,unix:listen:${sockDir}/l.sock,endpoint:logs`,
      dns: 'gateway:tcp:localhost:*',
      udp: 'gateway:udp:127.0.0.1:9',
      onWeb: 'exec,target:web',
      expired: 'exec',
    };
    const lines = [];
    for (const [name, c] of Object.entries(caps)) {
      const keyPair = await generateKeyPair(true);
      keys[name] = { keyPair };
      const expires = name === 'expired' ? `,expires="${past}"` : (name === 'exec' ? `,expires="${future}"` : '');
      lines.push(`capabilities="${c}"${expires} ${await exportPublicKeySSH(keyPair.publicKey)} ${name}@test`);
    }
    const labelled = (label) => async (command, io) => { execCalls.push(`${label}:${command}`); await io.write(`${label}:${command}\n`); return 0; };
    server = createWshServer({
      auth: { authorizedKeys: `${lines.join('\n')}\n` },
      exec: labelled('own'),
      pty: { spawn: () => ({ onData() {}, onExit() {}, write() {}, resize() {}, kill() {} }), shell: '/bin/sh' },
      fs: { root },
      rpc: { 'wsh-host': true, 'wsh-fs': true },
      mcp: { tools: [
        { name: 'echo', description: 'echo', call: async () => 'pong' },
        { name: 'shell', description: 'shell', call: async () => 'rooted' },
      ] },
      gateway: {
        allow: ['*'], allowPrivate: ['127.0.0.0/8'],
        unix: { connect: [`${sockDir}/`], listen: [`${sockDir}/`] },
        reverse: {},
        endpoints: {
          logs: async (duplex) => { const w = duplex.writable.getWriter(); await w.write(new TextEncoder().encode('logs')); await w.close(); },
          db: async (duplex) => { await duplex.writable.getWriter().close(); },
        },
        udp: { allow: ['*'] },
      },
      targets: { web: { exec: labelled('web') }, db: { exec: labelled('db') } },
      relay: { canRegister: () => true, canConnect: () => true },
      onRefused: (r) => refused.push(r),
      onLog: (l) => logs.push(l),
    });
    const { port } = await server.listen();
    url = `ws://127.0.0.1:${port}`;
  });
  after(async () => {
    for (const c of clients.splice(0)) await c.disconnect().catch(() => {});
    await server.close();
    echo.close(); unixServer.close();
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(sockDir, { recursive: true, force: true });
  });

  async function login(name) {
    const c = new WshClient();
    await c.connect(url, { username: 'alice', keyPair: keys[name].keyPair });
    clients.push(c);
    return c;
  }
  /** Refused with a reason matching `re`: a rejection (an Open, a gateway open) or a failed FileResult. */
  const refusedWith = async (promise, re) => {
    let r;
    try { r = await promise; } catch (e) { assert.match(String(e.message), re); return; }
    assert.equal(r?.success, false, `the request was served: ${JSON.stringify(r)}`);
    assert.match(String(r.error_message ?? r.errorMessage), re);
  };
  const output = (session) => new Promise((resolve) => { const out = []; session.onData = (d) => out.push(dec.decode(d)); session.onClose = () => resolve(out.join('')); });
  const run = async (client, command, opts) => output(await client.openSession({ type: 'exec', command, ...opts }));

  it('the reasons onRefused can give include the two this adds', () => {
    assert.ok(REFUSAL_REASONS.includes('not-permitted') && REFUSAL_REASONS.includes('key-expired'));
  });

  it('exec and pty: each needs its own capability, and pty does not imply exec', async () => {
    const e = await login('exec');
    assert.equal(await run(e, 'a'), 'own:a\n');
    await refusedWith(e.openSession({ type: 'pty' }), /missing capability pty/);
    const p = await login('pty');
    assert.ok(await p.openSession({ type: 'pty' }));
    await refusedWith(p.openSession({ type: 'exec', command: 'a' }), /missing capability exec/);
  });

  it('a key with an empty capability list can do nothing', async () => {
    const c = await login('nothing');
    await refusedWith(c.openSession({ type: 'exec', command: 'a' }), /missing capability exec/);
    await refusedWith(c.openSession({ type: 'pty' }), /missing capability pty/);
    await refusedWith(c.fileOperation('list', '/'), /missing capability fs:read/);
    await refusedWith(c.openSession({ type: 'rpc', protocol: 'wsh-host' }), /missing capability rpc:wsh-host/);
    assert.deepEqual(await c.discoverTools(), []);
  });

  it('fs:read serves list, stat, read and download, and refuses every write', async () => {
    const c = await login('fsRead');
    assert.ok((await c.fileOperation('list', '/')).entries.some((e) => e.name === 'hello.txt'));
    assert.equal(dec.decode(await c.download('/hello.txt')), 'hello');
    await refusedWith(c.fileOperation('write', '/x.txt', { data: 'x' }), /missing capability fs:write/);
    await refusedWith(c.fileOperation('mkdir', '/d'), /missing capability fs:write/);
    await refusedWith(c.fileOperation('remove', '/hello.txt'), /missing capability fs:write/);
    await refusedWith(c.fileOperation('rename', '/hello.txt', { newPath: '/h2.txt' }), /missing capability fs:write/);
    await refusedWith(c.upload(new Blob(['x']), '/up.txt'), /missing capability fs:write/);
    assert.ok(fs.existsSync(path.join(root, 'hello.txt')) && !fs.existsSync(path.join(root, 'up.txt')));
  });

  it('fs:write serves write, mkdir, rename, remove and upload, and refuses every read', async () => {
    const c = await login('fsWrite');
    await c.upload(new Blob(['up']), '/up.txt');
    assert.equal(fs.readFileSync(path.join(root, 'up.txt'), 'utf8'), 'up');
    assert.equal((await c.fileOperation('write', '/w.txt', { data: 'w' })).success, true);
    assert.equal((await c.fileOperation('mkdir', '/dir')).success, true);
    assert.equal((await c.fileOperation('rename', '/w.txt', { newPath: '/w2.txt' })).success, true);
    assert.equal((await c.fileOperation('remove', '/w2.txt')).success, true);
    await refusedWith(c.fileOperation('list', '/'), /missing capability fs:read/);
    await refusedWith(c.fileOperation('stat', '/hello.txt'), /missing capability fs:read/);
    await refusedWith(c.download('/hello.txt'), /missing capability fs:read/);
  });

  it('wsh-fs (read and write methods on one channel) needs both fs:read and fs:write', async () => {
    const both = await login('fsBoth');
    assert.ok(await both.openSession({ type: 'rpc', protocol: 'wsh-fs' }));
    const r = await login('fsRead');
    await refusedWith(r.openSession({ type: 'rpc', protocol: 'wsh-fs' }), /missing capability fs:write/);
    // ... and the client's file helpers fall back to FileOp, where each operation is checked
    assert.ok((await r.fileOperation('list', '/')).entries.length);
  });

  it('mcp:echo lists and calls echo only; mcp:* lists and calls everything and opens the mcp rpc channel', async () => {
    const one = await login('mcpEcho');
    assert.deepEqual((await one.discoverTools()).map((t) => t.name), ['echo']);
    assert.ok(await one.callTool('echo', {}));
    const refusal = await one.callTool('shell', {});
    assert.equal(refusal.success, false);
    assert.match(refusal.error, /missing capability mcp:shell/);
    const none = await login('exec');
    assert.deepEqual(await none.discoverTools(), []);
    assert.match((await none.callTool('echo', {})).error, /missing capability mcp:echo/);
    const all = await login('mcpAll');
    assert.deepEqual((await all.discoverTools()).map((t) => t.name).sort(), ['echo', 'shell']);
    assert.equal(await all.callTool('shell', {}) !== undefined, true);
  });

  it('relay: registering, listing and connecting need the relay capability', async () => {
    const ok = new WshClient();
    await ok.connectReverse(url, { username: 'alice', keyPair: keys.relay.keyPair, expose: { exec: true } });
    clients.push(ok);
    await until(() => server.peerFingerprints().length === 1, 'the permitted peer to register');
    const denied = new WshClient();
    await denied.connectReverse(url, { username: 'alice', keyPair: keys.exec.keyPair, expose: { exec: true } }).catch(() => {});
    clients.push(denied);
    await new Promise((r) => setTimeout(r, 120));
    assert.equal(server.peerFingerprints().length, 1, 'a key without the relay capability never registers');
    assert.ok(logs.some((l) => /refused relay/.test(l) && /capability-missing: relay/.test(l)), logs.join('\n'));
    const c = await login('exec');
    await assert.rejects(c.listPeers(150), /./);
  });

  it('gateway tcp: only the destination the capability names', async () => {
    const c = await login('gateway');
    const d = await c.openTcp('127.0.0.1', echoPort);
    const w = d.writable.getWriter();
    await w.write(new TextEncoder().encode('hi'));
    const r = d.readable.getReader();
    assert.equal(dec.decode((await r.read()).value), 'echo:hi');
    await d.writable.close().catch(() => {});
    await assert.rejects(c.openTcp('127.0.0.1', echoPort + 1), /missing capability gateway:tcp:127.0.0.1:/);
    await assert.rejects((await login('exec')).openTcp('127.0.0.1', echoPort), /missing capability gateway:tcp:127.0.0.1:/);
  });

  it('gateway listen (reverse tcp) and unix: separate capabilities, listening is not connecting', async () => {
    const c = await login('gateway');
    const handle = await c.listenTcp(0, { onConnection() {} });
    assert.ok(handle.port > 0);
    await handle.close();
    await assert.rejects((await login('exec')).listenTcp(0, { onConnection() {} }), /missing capability gateway:listen:tcp:0/);
    const u = await c.openUnix(path.join(sockDir, 'ok.sock'));
    const uw = u.writable.getWriter();
    await uw.write(new TextEncoder().encode('yo'));
    assert.equal(dec.decode((await u.readable.getReader().read()).value), 'unix:yo');
    await assert.rejects(c.openUnix(path.join(sockDir, 'other.sock')), /missing capability unix:/);
    await assert.rejects((await login('exec')).openUnix(path.join(sockDir, 'ok.sock')), /missing capability unix:/);
    const l = await c.listenUnix(path.join(sockDir, 'l.sock'), { onConnection() {} });
    await l.close();
    await assert.rejects(c.listenUnix(path.join(sockDir, 'ok2.sock'), { onConnection() {} }), /missing capability unix:listen:/);
  });

  it('endpoints: the named endpoint, not another', async () => {
    const c = await login('gateway');
    const e = await c.openEndpoint('logs');
    assert.equal(dec.decode((await e.readable.getReader().read()).value), 'logs');
    await assert.rejects(c.openEndpoint('db'), /missing capability endpoint:db/);
    await assert.rejects((await login('exec')).openEndpoint('logs'), /missing capability endpoint:logs/);
  });

  it('dns and udp: a name the key may connect to, and udp only with its own capability', async () => {
    const asker = async (name) => {
      const c = await login(name);
      const inbox = [];
      c.onGatewayMessage = (m) => inbox.push(m);
      return { c, inbox };
    };
    const { c, inbox } = await asker('dns');
    await c.sendControl(resolveDnsMsg({ gatewayId: 1, name: 'localhost' }));
    await until(() => inbox.length, 'a DNS answer');
    assert.ok(!JSON.stringify(inbox[0]).includes('missing capability'), 'the capability covers the name');
    const other = await asker('exec');
    await other.c.sendControl(resolveDnsMsg({ gatewayId: 2, name: 'localhost' }));
    await until(() => other.inbox.length, 'a refusal');
    assert.match(JSON.stringify(other.inbox[0]), /missing capability gateway:tcp:localhost:\*/);
    const udp = await asker('exec');
    await udp.c.sendControl(openUdpMsg({ gatewayId: 3, host: '127.0.0.1', port: 9 }));
    await until(() => udp.inbox.length, 'a udp refusal');
    assert.match(JSON.stringify(udp.inbox[0]), /missing capability gateway:udp:127.0.0.1:9/);
    const allowed = await asker('udp');
    await allowed.c.sendControl(openUdpMsg({ gatewayId: 4, host: '127.0.0.1', port: 9 }));
    await until(() => allowed.inbox.length, 'an answer');
    assert.ok(!JSON.stringify(allowed.inbox[0]).includes('missing capability'));
  });

  it('targets: target:NAME names a target; listing shows only those the key holds; the host itself needs none', async () => {
    const c = await login('onWeb');
    assert.equal(await run(c, 'a', { target: 'web' }), 'web:a\n');
    await refusedWith(c.openSession({ type: 'exec', command: 'a', target: 'db' }), /missing capability target:db/);
    assert.deepEqual((await c.listTargets()).map((t) => t.name), ['web']);
    assert.equal(await run(c, 'own'), 'own:own\n');
    const e = await login('exec');
    await refusedWith(e.openSession({ type: 'exec', command: 'a', target: 'web' }), /missing capability target:web/);
    assert.deepEqual(await e.listTargets(), []);
    await refusedWith(c.fileOperation('list', '/', { target: 'web' }), /missing capability fs:read/);
  });

  it('expires: a key past its expiry does not log in, and says so to onRefused and the log', async () => {
    const c = new WshClient();
    await assert.rejects(c.connect(url, { username: 'alice', keyPair: keys.expired.keyPair }), /expired/);
    assert.ok(refused.some((r) => r.reason === 'key-expired' && r.who.username === 'alice'), JSON.stringify(refused));
    const ok = await login('exec');
    assert.equal(await run(ok, 'a'), 'own:a\n');
  });

  it('onRefused hears every request a capability refused, with a stable reason and the missing capability', async () => {
    const before = refused.length;
    const c = await login('exec');
    await refusedWith(c.openSession({ type: 'pty' }), /missing capability pty/);
    await refusedWith(c.fileOperation('list', '/'), /missing capability fs:read/);
    const mine = refused.slice(before);
    assert.ok(mine.every((r) => REFUSAL_REASONS.includes(r.reason)));
    assert.ok(mine.some((r) => r.reason === 'not-permitted' && /capability-missing: missing capability pty/.test(r.detail)), JSON.stringify(mine));
    assert.ok(mine.some((r) => r.reason === 'not-permitted' && /missing capability fs:read/.test(r.detail)));
    assert.ok(mine.every((r) => r.who.fingerprint && r.who.username === 'alice'));
  });
});

describe('capabilities returned by authorize() (#122, step two)', () => {
  const clients = []; let server; let url; let kp; let grantFor = () => true;
  const logs = [];
  before(async () => {
    kp = await generateKeyPair(true);
    server = createWshServer({
      auth: { authorizedKeys: `restrict,permit-exec,permit-pty ${await exportPublicKeySSH(kp.publicKey)} a`, authorize: (who) => grantFor(who) },
      exec: async (cmd, io) => { await io.write(`ran:${cmd}\n`); return 0; },
      pty: { spawn: () => ({ onData() {}, onExit() {}, write() {}, resize() {}, kill() {} }), shell: '/bin/sh' },
      onLog: (l) => logs.push(l),
    });
    url = `ws://127.0.0.1:${(await server.listen()).port}`;
  });
  after(async () => { for (const c of clients.splice(0)) await c.disconnect().catch(() => {}); await server.close(); });
  const login = async () => { const c = new WshClient(); await c.connect(url, { username: 'alice', keyPair: kp }); clients.push(c); return c; };

  it('true keeps working: the key line alone decides', async () => {
    grantFor = () => true;
    const c = await login();
    assert.ok(await c.openSession({ type: 'pty' }));
  });

  it('a capability set narrows what the key line allows', async () => {
    grantFor = () => ({ capabilities: ['exec'] });
    const c = await login();
    const s = await c.openSession({ type: 'exec', command: 'a' });
    assert.ok(s);
    await assert.rejects(c.openSession({ type: 'pty' }), /missing capability pty/);
  });

  it('it never widens it: the key line still refuses what it does not permit', async () => {
    grantFor = () => ({ capabilities: 'exec,fs:read' });
    const c = await login();
    await assert.rejects(c.fileOperation('list', '/').then((r) => { if (r.success === false) throw new Error(r.error_message); return r; }), /not enabled|not permitted/);
  });

  it('a string is the same comma-separated grammar, and an unknown capability refuses the login', async () => {
    grantFor = () => ({ capabilities: 'exec,teleport' });
    const c = new WshClient();
    await assert.rejects(c.connect(url, { username: 'alice', keyPair: kp }), /not authorized/);
    assert.ok(logs.some((l) => /unknown-capability/.test(l) && /teleport/.test(l)), logs.join('\n'));
  });

  it('expires on the grant: served until it passes, then every request is refused as expired', async () => {
    // Expiry is in whole seconds: the key is good until the second after this one begins.
    const at = (Math.floor(Date.now() / 1000) + 2) * 1000;
    grantFor = () => ({ capabilities: ['exec'], expires: new Date(at) });
    const c = await login();
    assert.ok(await c.openSession({ type: 'exec', command: 'a' }));
    await new Promise((r) => setTimeout(r, Math.max(0, at - Date.now()) + 50));
    await assert.rejects(c.openSession({ type: 'exec', command: 'b' }), /expired/);
    await assert.rejects(login(), /expired/);
  });
});
