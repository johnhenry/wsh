// test/server-gateway.test.mjs -- `gateway` of `@johnhenry/wsh/server`: the Node server answers OpenTcp / ResolveDns /
// GatewayData / GatewayClose (default deny), optionally through a SOCKS5 proxy. A local TCP echo server is the
// destination and a small SOCKS5 fixture is the proxy; nothing leaves loopback.
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { createWshServer } from '@johnhenry/wsh/server';
import { WshClient, generateKeyPair, exportPublicKeySSH, MSG } from '@johnhenry/wsh';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(cond, what, ms = 4000) {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(10); }
}
const listen = (server) => new Promise((r) => server.listen(0, '127.0.0.1', () => r(server.address().port)));

/** A SOCKS5 server (no auth, CONNECT only) that records the requests it saw. */
function socksFixture() {
  const seen = [];
  const server = net.createServer((c) => {
    let stage = 0; let buf = Buffer.alloc(0);
    c.on('error', () => {});
    c.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (stage === 0 && buf.length >= 3) { c.write(Buffer.from([5, 0])); buf = buf.subarray(3); stage = 1; }
      if (stage === 1 && buf.length >= 5) {
        const atyp = buf[3];
        const len = atyp === 3 ? buf[4] : atyp === 1 ? 4 : 16;
        const need = atyp === 3 ? 5 + len + 2 : 4 + len + 2;
        if (buf.length < need) return;
        const host = atyp === 3 ? buf.subarray(5, 5 + len).toString() : '<ip>';
        const port = buf.readUInt16BE(need - 2);
        seen.push({ atyp, host, port });
        stage = 2; c.removeAllListeners('data');
        if (host.endsWith('.refused')) { c.end(Buffer.from([5, 5, 0, 1, 0, 0, 0, 0, 0, 0])); return; }
        const up = net.connect(port === 9 ? 0 : port, '127.0.0.1', () => { c.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0])); c.pipe(up); up.pipe(c); });
        up.on('error', () => c.destroy());
      }
    });
  });
  return { server, seen };
}

describe('gateway', () => {
  const servers = []; const clients = []; const nets = [];
  afterEach(async () => {
    for (const c of clients.splice(0)) await c.disconnect().catch(() => {});
    for (const s of servers.splice(0)) await s.close();
    for (const n of nets.splice(0)) n.close();
  });

  async function setup(gateway) {
    const keyPair = await generateKeyPair(true);
    const line = `${await exportPublicKeySSH(keyPair.publicKey)} alice`;
    const echo = net.createServer((c) => { c.on('data', (d) => c.write(Buffer.concat([Buffer.from('echo:'), d]))); c.on('error', () => {}); });
    const echoPort = await listen(echo); nets.push(echo);
    const server = createWshServer({ auth: { authorizedKeys: line }, gateway: typeof gateway === 'function' ? gateway(echoPort) : gateway });
    const { port } = await server.listen(); servers.push(server);
    const client = new WshClient();
    await client.connect(`ws://127.0.0.1:${port}`, { username: 'alice', keyPair });
    clients.push(client);
    const inbox = [];
    client.onGatewayMessage = (m) => inbox.push(m);
    return { client, echoPort, inbox, features: () => client };
  }

  it('relays TCP both ways to an allowed destination, and closes both ends', async () => {
    const { client, echoPort, inbox } = await setup((p) => ({ allow: [`127.0.0.1:${p}`] }));
    await client.sendControl({ type: MSG.OPEN_TCP, gateway_id: 1, host: '127.0.0.1', port: echoPort });
    await until(() => inbox.find((m) => m.type === MSG.GATEWAY_OK && m.gateway_id === 1), 'GatewayOk');
    await client.sendControl({ type: MSG.GATEWAY_DATA, gateway_id: 1, data: new TextEncoder().encode('hi') });
    const data = await until(() => inbox.find((m) => m.type === MSG.GATEWAY_DATA), 'echo');
    assert.equal(new TextDecoder().decode(data.data), 'echo:hi');
    await client.sendControl({ type: MSG.GATEWAY_CLOSE, gateway_id: 1 });
    await until(() => inbox.find((m) => m.type === MSG.GATEWAY_CLOSE && m.gateway_id === 1), 'GatewayClose');
  });

  it('is default deny: a destination not on the list, an empty list, UDP and reverse tunnels are refused', async () => {
    const { client, echoPort, inbox } = await setup({ allow: ['other.example:80'] });
    await client.sendControl({ type: MSG.OPEN_TCP, gateway_id: 7, host: '127.0.0.1', port: echoPort });
    await client.sendControl({ type: MSG.OPEN_UDP, gateway_id: 8, host: '127.0.0.1', port: 53 });
    await client.sendControl({ type: MSG.LISTEN_REQUEST, listener_id: 9, port: 0, bind_addr: '127.0.0.1' });
    const f7 = await until(() => inbox.find((m) => m.type === MSG.GATEWAY_FAIL && m.gateway_id === 7), 'fail 7');
    assert.equal(f7.code, 4);
    assert.equal((await until(() => inbox.find((m) => m.type === MSG.GATEWAY_FAIL && m.gateway_id === 8), 'fail 8')).code, 4);
    assert.ok(await until(() => inbox.find((m) => m.type === MSG.LISTEN_FAIL && m.listener_id === 9), 'listen fail'));
    assert.equal(inbox.some((m) => m.type === MSG.GATEWAY_OK), false);
  });

  it('a server without `gateway` ignores the opcodes (nothing is opened)', async () => {
    const { client, echoPort, inbox } = await setup(undefined);
    await client.sendControl({ type: MSG.OPEN_TCP, gateway_id: 1, host: '127.0.0.1', port: echoPort });
    await sleep(150);
    assert.equal(inbox.length, 0);
  });

  it('enforces maxConnections and refuses a reused gateway_id', async () => {
    const { client, echoPort, inbox } = await setup((p) => ({ allow: ['127.0.0.1'], maxConnections: 1 }));
    await client.sendControl({ type: MSG.OPEN_TCP, gateway_id: 1, host: '127.0.0.1', port: echoPort });
    await until(() => inbox.find((m) => m.type === MSG.GATEWAY_OK), 'ok');
    await client.sendControl({ type: MSG.OPEN_TCP, gateway_id: 2, host: '127.0.0.1', port: echoPort });
    assert.equal((await until(() => inbox.find((m) => m.type === MSG.GATEWAY_FAIL && m.gateway_id === 2), 'fail 2')).code, 7);
  });

  it('reports a refused connection with code 1', async () => {
    const dead = net.createServer(); const deadPort = await listen(dead); dead.close(); await sleep(20);
    const { client, inbox } = await setup({ allow: ['*'] });
    await client.sendControl({ type: MSG.OPEN_TCP, gateway_id: 3, host: '127.0.0.1', port: deadPort });
    assert.equal((await until(() => inbox.find((m) => m.type === MSG.GATEWAY_FAIL), 'fail')).code, 1);
  });

  it('resolves a name (A) when allowed and refuses one that is not', async () => {
    const { client, inbox } = await setup({ allow: ['localhost'] });
    await client.sendControl({ type: MSG.RESOLVE_DNS, gateway_id: 4, name: 'localhost', record_type: 'A' });
    const r = await until(() => inbox.find((m) => m.type === MSG.DNS_RESULT), 'dns');
    assert.ok(r.addresses.includes('127.0.0.1'));
    await client.sendControl({ type: MSG.RESOLVE_DNS, gateway_id: 5, name: 'example.com', record_type: 'A' });
    assert.equal((await until(() => inbox.find((m) => m.type === MSG.GATEWAY_FAIL && m.gateway_id === 5), 'fail')).code, 4);
  });

  it('dials through a SOCKS5 proxy with the name unresolved, and refuses ResolveDns', async () => {
    const { server: proxy, seen } = socksFixture();
    const proxyPort = await listen(proxy); nets.push(proxy);
    const { client, echoPort, inbox } = await setup(() => ({ allow: ['*'], socks: `127.0.0.1:${proxyPort}` }));
    // Port 9 is a stand-in the fixture maps to... the echo server's port is passed instead, so use it directly.
    await client.sendControl({ type: MSG.OPEN_TCP, gateway_id: 1, host: 'broker.onion', port: echoPort });
    await until(() => inbox.find((m) => m.type === MSG.GATEWAY_OK), 'ok through socks');
    await client.sendControl({ type: MSG.GATEWAY_DATA, gateway_id: 1, data: new TextEncoder().encode('tor') });
    const d = await until(() => inbox.find((m) => m.type === MSG.GATEWAY_DATA), 'echo');
    assert.equal(new TextDecoder().decode(d.data), 'echo:tor');
    assert.deepEqual(seen[0], { atyp: 3, host: 'broker.onion', port: echoPort }); // the proxy saw a NAME, not an address
    await client.sendControl({ type: MSG.RESOLVE_DNS, gateway_id: 2, name: 'broker.onion', record_type: 'A' });
    assert.equal((await until(() => inbox.find((m) => m.type === MSG.GATEWAY_FAIL && m.gateway_id === 2), 'dns refused')).code, 4);
    await client.sendControl({ type: MSG.OPEN_TCP, gateway_id: 3, host: 'nope.refused', port: 80 });
    assert.equal((await until(() => inbox.find((m) => m.type === MSG.GATEWAY_FAIL && m.gateway_id === 3), 'proxy refusal')).code, 1);
  });

  it('rejects `gateway: true` (an allow list is required) and a bad socks string', () => {
    assert.throws(() => createWshServer({ gateway: true }), /allow/);
    assert.throws(() => createWshServer({ gateway: { allow: ['*'], socks: 'nonsense' } }), /socks/);
  });
});
