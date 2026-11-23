// test/channel-binding.test.mjs -- #119: the login signature is bound to the connection it was made over.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer as createHttpsServer } from 'node:https';
import { WebSocketServer, WebSocket as WsClientSocket } from 'ws';
import { createWshServer } from '@johnhenry/wsh/server';
import { WshClient, generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';
import {
  computeChannelBinding, acceptableBindings, clientChannelBinding, offeredKinds, bindingFeatures, requiresBinding,
} from '../src/channel-binding.mjs';
import { buildTranscript } from '../src/auth.mjs';
import { generateSelfSignedCertificate } from '../src/server/self-signed.mjs';
import { WebSocketTransport } from '../src/transport-ws.mjs';
import { QMuxConnection } from '../src/qmux-connection.mjs';
import { FrameDecoder, frameEncode } from '../src/cbor.mjs';
import { MSG } from '../src/messages.gen.mjs';
import { HOST_KEY_PREFIX, HOST_KEY_SIG_PREFIX, hostKeyProofMessage, findClientNonce, toHex } from '../src/host-key.mjs';
import { loadHostKey } from '../src/server/host-key.mjs';

const hex = (b) => Buffer.from(b).toString('hex');
const fill = (n, v) => new Uint8Array(n).fill(v);
const dec = new TextDecoder();

describe('channel binding: the value', () => {
  // Test vectors (also printed in spec/wsh-v1.yaml, Auth). The digests below were computed from the byte layout
  // alone, independently of the implementation:
  //   SHA-256( "wsh-channel-binding-v1\0" || for each kind present, in this order: lp(kind) || lp(value) )
  // with lp = 4-byte big-endian length prefix and the kinds ordered cert-hash, host, tls-exporter.
  const lp = (b) => Buffer.concat([Buffer.from([0, 0, 0, b.length]), Buffer.from(b)]);
  const label = Buffer.from('wsh-channel-binding-v1\0');
  const cert = fill(32, 0x11); const host = fill(32, 0x22); const exp = fill(32, 0x33);
  const VECTOR_HOST = '266d39f1ffe60713ab836382fa8373407c8facaa88a3ddaf80c1cd5433e80dcc';
  const VECTOR_ALL = 'dc2256bcbd4bff249870321a14390d305147a1e4e6dc701c0a3fc3dfff750da7';

  it('no kind -> the empty binding, exactly what the transcript carried before', async () => {
    assert.equal((await computeChannelBinding({})).length, 0);
    assert.equal((await computeChannelBinding({ unknown: cert })).length, 0);
  });

  it('vector 1 (host = 32 x 0x22) and vector 2 (cert-hash 32 x 0x11, host 32 x 0x22, tls-exporter 32 x 0x33)', async () => {
    assert.equal(hex(await computeChannelBinding({ host })), VECTOR_HOST);
    assert.equal(hex(await computeChannelBinding({ 'tls-exporter': exp, host, 'cert-hash': cert })), VECTOR_ALL);
    // ... and the constants really are the layout above.
    assert.equal(createHash('sha256').update(Buffer.concat([label, lp(Buffer.from('host')), lp(host)])).digest('hex'), VECTOR_HOST);
  });

  it('the transcript with an empty binding is byte-identical to the one released peers sign', async () => {
    const a = await buildTranscript('sid', fill(32, 1), { username: 'alice' });
    const b = await buildTranscript('sid', fill(32, 1), { username: 'alice', channelBinding: await computeChannelBinding({}) });
    assert.deepEqual(a, b);
    const c = await buildTranscript('sid', fill(32, 1), { username: 'alice', channelBinding: await computeChannelBinding({ host }) });
    assert.notDeepEqual(a, c);
  });

  it('features: offered kinds parse in canonical order; required is separate', () => {
    const f = bindingFeatures(['tls-exporter', 'host'], { required: true });
    assert.deepEqual(f, ['channel-binding:tls-exporter', 'channel-binding:host', 'channel-binding-required']);
    assert.deepEqual(offeredKinds([...f, 'channel-binding:nonsense', 'e2e']), ['host', 'tls-exporter']);
    assert.equal(requiresBinding(f), true);
    assert.equal(requiresBinding(['channel-binding:host']), false);
  });

  it('the client binds what is offered AND available; the host accepts every combination it could have been sent', async () => {
    const offered = bindingFeatures(['host', 'tls-exporter']);
    const { binding, kinds } = await clientChannelBinding(offered, { host, 'cert-hash': cert }); // a browser: no exporter; cert not offered
    assert.deepEqual(kinds, ['host']);
    const held = { host: [host], 'tls-exporter': [exp] };
    const acc = await acceptableBindings(held, { required: false });
    assert.equal(acc.length, 4); // {}, {host}, {exporter}, {host, exporter}
    assert.ok(acc.some((a) => hex(a.binding) === hex(binding)));
    assert.equal((await acceptableBindings(held, { required: true })).length, 3); // not the empty one
    assert.equal((await acceptableBindings(held, { required: ['tls-exporter'] })).length, 2);
    assert.equal((await acceptableBindings({ 'cert-hash': [cert, fill(32, 0x44)] }, { required: true })).length, 2); // a rotating certificate
  });
});

/**
 * An intermediary: a wsh "server" to the client, a wsh client to the real host, that forwards every control message
 * and optionally tampers with the ServerHello -- the relaying attacker of the issue. `swapKey` presents its own host
 * key (with a valid proof of possession for this connection); `strip` removes the host's `channel-binding*` offers.
 */
async function intermediary(upstream, { swapKey = false, strip = false, tls = null } = {}) {
  const own = swapKey ? await loadHostKey(true) : null;
  const server = tls ? createHttpsServer(tls) : null;
  const wss = server ? new WebSocketServer({ server }) : new WebSocketServer({ port: 0, host: '127.0.0.1' });
  const port = await new Promise((resolve) => {
    if (server) server.listen(0, '127.0.0.1', () => resolve(server.address().port));
    else wss.once('listening', () => resolve(wss.address().port));
  });
  const seen = [];
  wss.on('connection', (ws) => {
    const qmux = new QMuxConnection({ isClient: false, send: (b) => { if (ws.readyState === 1) ws.send(b); } });
    const decoder = new FrameDecoder();
    let control = null;
    let username = ''; let nonce = null;
    const back = new WebSocketTransport({ WebSocket: WsClientSocket });
    const ready = back.connect(upstream);
    back.onControl = async (m) => {
      seen.push(m.type);
      let out = m;
      if (m.type === MSG.SERVER_HELLO) {
        let features = (m.features ?? []).filter((f) => !(strip && f.startsWith('channel-binding')));
        if (own) {
          features = features.filter((f) => !f.startsWith(HOST_KEY_PREFIX) && !f.startsWith(HOST_KEY_SIG_PREFIX));
          const sig = await own.sign(hostKeyProofMessage({ sessionId: m.session_id, clientNonce: nonce, username }));
          features.push(HOST_KEY_PREFIX + toHex(own.publicKey), HOST_KEY_SIG_PREFIX + toHex(sig));
        }
        out = { ...m, features, ...(own ? { host_fingerprint: own.fingerprint } : {}) };
      }
      await control?.write(frameEncode(out));
    };
    qmux.onStreamOpen = (s) => {
      if (s.id !== 0) return;
      control = s;
      s.onData = (d) => {
        for (const m of decoder.feed(d)) {
          if (m.type === MSG.HELLO) { username = m.username; nonce = findClientNonce(m.features); }
          ready.then(() => back.sendControl(m));
        }
      };
    };
    qmux.sendHandshake();
    ws.on('message', (d) => qmux.receiveBytes(new Uint8Array(d)));
    ws.on('close', () => back.close().catch(() => {}));
  });
  return {
    url: `${tls ? 'wss' : 'ws'}://127.0.0.1:${port}`, seen, hostKey: own,
    close: async () => { for (const c of wss.clients) c.terminate(); await new Promise((r) => wss.close(r)); server?.close(); },
  };
}

describe('channel binding on a connection', () => {
  let keyPair; let authorizedKeys; let savedTls;
  const toClose = [];
  before(async () => {
    savedTls = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // self-signed test certificates
    keyPair = await generateKeyPair(true);
    authorizedKeys = `${await exportPublicKeySSH(keyPair.publicKey)} alice@test\n`;
  });
  after(async () => {
    if (savedTls === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED; else process.env.NODE_TLS_REJECT_UNAUTHORIZED = savedTls;
    for (const c of toClose.splice(0).reverse()) await c();
  });

  async function host(opts = {}) {
    const server = createWshServer({ auth: { authorizedKeys }, exec: true, ...opts });
    const { port } = await server.listen();
    toClose.push(() => server.close());
    return { server, url: `${opts.tls ? 'wss' : 'ws'}://127.0.0.1:${port}` };
  }
  async function relay(url, opts) {
    const r = await intermediary(url, opts);
    toClose.push(() => r.close());
    return r;
  }
  const wsClient = () => new WshClient({ transportFactories: { ws: () => new WebSocketTransport({ WebSocket: WsClientSocket }) } });
  async function login(url, opts = {}, client = new WshClient()) {
    await client.connect(url, { username: 'alice', keyPair, timeout: 4000, ...opts });
    toClose.push(() => client.disconnect().catch(() => {}));
    return client;
  }
  const echo = async (client) => {
    const s = await client.openSession({ type: 'exec', command: 'echo bound' });
    return new Promise((resolve) => { const ch = []; s.onData = (d) => ch.push(d); s.onClose = () => resolve(dec.decode(Buffer.concat(ch))); });
  };

  it('a host with a key binds the signature to it; a host that requires a binding accepts that client', async () => {
    const h = await host({ hostKey: true, requireChannelBinding: true });
    const client = await login(h.url, { requireChannelBinding: true });
    assert.deepEqual(client.channelBinding, ['host']);
    assert.equal(await echo(client), 'bound\n');
  });

  it('with no host key and a plain ws:// there is nothing to bind: a requiring host refuses everyone, and says why', async () => {
    const h = await host({ requireChannelBinding: true });
    await assert.rejects(login(h.url), /channel binding required/);
    await assert.rejects(login(h.url, { requireChannelBinding: true }), /channel binding required but not available/);
  });

  it('a host that does not require it still accepts an unbound login (released clients keep working)', async () => {
    const h = await host({ hostKey: true });
    const client = await login(h.url);
    assert.deepEqual(client.channelBinding, ['host']); // a new client binds whenever it is offered
    const plain = await host({});
    const c2 = await login(plain.url);
    assert.deepEqual(c2.channelBinding, []);
  });

  it('a transparent byte relay is not an attack: the client and host agree on the host key', async () => {
    const h = await host({ hostKey: true, requireChannelBinding: true });
    const r = await relay(h.url);
    const client = await login(r.url, { requireChannelBinding: true });
    assert.deepEqual(client.channelBinding, ["host"]); // a control-only relay: no data streams here
  });

  it('a relaying intermediary with its own host key fails: the client binds the key it saw, the host expects its own', async () => {
    for (const requireChannelBinding of [false, true]) {
      const h = await host({ hostKey: true, requireChannelBinding });
      const r = await relay(h.url, { swapKey: true });
      await assert.rejects(login(r.url), /signature does not verify/, `host requires binding: ${requireChannelBinding}`);
    }
  });

  it('an intermediary that strips the offer: a host that requires binding refuses, and so does a client that requires it', async () => {
    const h = await host({ hostKey: true, requireChannelBinding: true });
    const r = await relay(h.url, { swapKey: true, strip: true });
    await assert.rejects(login(r.url), /channel binding required/);
    await assert.rejects(login(r.url, { requireChannelBinding: true }), /channel binding required but not available/);
    assert.ok(!r.seen.includes(MSG.AUTH_OK));
  });

  it('LIMIT: strip + swap against a host that does not require binding and a client that does not either, succeeds', async () => {
    const h = await host({ hostKey: true });
    const r = await relay(h.url, { swapKey: true, strip: true });
    const client = await login(r.url); // no pin, no requirement: nothing could tell this from the real host
    assert.deepEqual(client.channelBinding, []);
    assert.ok(r.seen.includes(MSG.AUTH_OK));
  });

  it('a pinned host key still refuses the swapped key, before any signature is made', async () => {
    const h = await host({ hostKey: true });
    const r = await relay(h.url, { swapKey: true, strip: true });
    await assert.rejects(login(r.url, { expectHostKey: h.server ? (await loadHostKey(true)).fingerprint : '' }), /host key/i);
  });

  describe('tls-exporter (Node, wss:// served by this process)', () => {
    let cert; let relayCert;
    before(() => { cert = generateSelfSignedCertificate(); relayCert = generateSelfSignedCertificate(); });
    const tls = () => ({ cert: cert.cert, key: cert.privKey });

    it('both ends compute the same exporter: a host can require it of a Node client', async () => {
      const h = await host({ tls: tls(), requireChannelBinding: ['tls-exporter'] });
      const client = await login(h.url, { requireChannelBinding: ['tls-exporter'] }, wsClient());
      assert.deepEqual(client.channelBinding, ['tls-exporter']);
      assert.equal(await echo(client), 'bound\n');
    });

    it('a client without an exporter (Node global WebSocket, a browser) cannot satisfy a host that requires one', async () => {
      const h = await host({ tls: tls(), requireChannelBinding: ['tls-exporter'] });
      await assert.rejects(login(h.url), /channel binding required/);
      await assert.rejects(login(h.url, { requireChannelBinding: ['tls-exporter'] }), /channel binding required but not available/);
    });

    it('a TLS-terminating intermediary fails even though its own TLS is valid: the exporters differ', async () => {
      const h = await host({ tls: tls(), requireChannelBinding: ['tls-exporter'] });
      const r = await relay(h.url, { tls: { cert: relayCert.cert, key: relayCert.privKey } });
      await assert.rejects(login(r.url, {}, wsClient()), /signature does not verify/);
      // ... and stripping the offer does not help it: the host still requires the exporter.
      const r2 = await relay(h.url, { tls: { cert: relayCert.cert, key: relayCert.privKey }, strip: true });
      await assert.rejects(login(r2.url, {}, wsClient()), /channel binding required/);
    });

    it('exporter and host key together', async () => {
      const h = await host({ tls: tls(), hostKey: true, requireChannelBinding: ['host', 'tls-exporter'] });
      const client = await login(h.url, { requireChannelBinding: ['host', 'tls-exporter'] }, wsClient());
      assert.deepEqual(client.channelBinding, ['host', 'tls-exporter']);
    });
  });

  it('rejects a nonsensical requireChannelBinding', () => {
    assert.throws(() => createWshServer({ requireChannelBinding: 'yes' }), /requireChannelBinding/);
    assert.throws(() => createWshServer({ requireChannelBinding: ['nope'] }), /requireChannelBinding/);
  });
});

// WebTransport: the pinned certificate hash. Needs the optional native packages; skipped with the reason where absent.
let wtLib = null;
let skipReason = false;
try {
  wtLib = await import('@fails-components/webtransport');
  await wtLib.quicheLoaded;
  const probe = generateSelfSignedCertificate();
  const s = new wtLib.Http3Server({ port: 0, host: '127.0.0.1', secret: 'probe', cert: probe.cert, privKey: probe.privKey });
  s.startServer();
  await s.ready;
  s.stopServer();
} catch (err) {
  skipReason = `the native WebTransport packages are unavailable (${String(err?.message ?? err).split('\n')[0]})`;
}

describe('channel binding over WebTransport (cert-hash)', { skip: skipReason }, () => {
  let keyPair; let authorizedKeys; let saved;
  before(async () => {
    keyPair = await generateKeyPair(true);
    authorizedKeys = `${await exportPublicKeySSH(keyPair.publicKey)} alice@test\n`;
    saved = globalThis.WebTransport;
    globalThis.WebTransport = wtLib.WebTransport;
  });
  after(() => { globalThis.WebTransport = saved; });

  it('a client that pinned the certificate binds to it, and a host can require it', async () => {
    const server = createWshServer({ auth: { authorizedKeys }, exec: true, webTransport: { selfSigned: true }, requireChannelBinding: ['cert-hash'] });
    await server.listen();
    const wt = server.webTransport();
    const client = new WshClient();
    try {
      await client.connect(wt.url, {
        username: 'alice', keyPair, transport: 'wt', requireChannelBinding: ['cert-hash'],
        webTransport: { serverCertificateHashes: [{ algorithm: 'sha-256', value: wt.certificateHash }] },
      });
      assert.deepEqual(client.channelBinding, ['cert-hash']);
    } finally { await client.disconnect().catch(() => {}); await server.close(); }
  });

  it('with two pinned hashes the client cannot say which one it met, so it binds none (and a requiring host refuses it)', async () => {
    const server = createWshServer({ auth: { authorizedKeys }, exec: true, webTransport: { selfSigned: true }, requireChannelBinding: ['cert-hash'] });
    await server.listen();
    const wt = server.webTransport();
    const client = new WshClient();
    try {
      await assert.rejects(client.connect(wt.url, {
        username: 'alice', keyPair, transport: 'wt', requireChannelBinding: true,
        webTransport: { serverCertificateHashes: [{ algorithm: 'sha-256', value: wt.certificateHash }, { algorithm: 'sha-256', value: fill(32, 9) }] },
      }), /channel binding required but not available/);
    } finally { await client.disconnect().catch(() => {}); await server.close(); }
  });
});
