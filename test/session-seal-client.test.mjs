// test/session-seal-client.test.mjs -- #155 stage c, PR 1: the JS client as the INITIATOR of a sealed session.
//
//   client.connect(url, { sealSession: false | 'auto' | true })
//
// against a JS host (`createMemoryHost({ sealSession })`) behind a relay that records, tampers, strips and injects
// (test/helpers/hostile-relay.mjs). The recording relay is the point: with the session sealed it finds neither the data nor the
// endpoint name; without it (control run) it finds both. A flipped bit, a replayed frame or a frame cut short closes the
// session; a plain message injected after the key exchange is not heard; `true` against a host that does not offer sealing is
// refused before a credential leaves the client.
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { WebSocketServer } from 'ws';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { WshClient, generateKeyPair, exportPublicKeySSH, MSG, cborEncode } from '@johnhenry/wsh';
import { hostileRelay } from './helpers/hostile-relay.mjs';

const MARKER = 'SECRET-MARKER-ZEBRA-7731';
const ENDPOINT = 'zebra-endpoint-name';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (cond, what, ms = 5000) => {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(15); }
};

const closers = [];
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });

/** A host behind a hostile relay: `{ host, relay, logs, keyPair }`; connect a client to `relay.url`. */
async function setup({ sealSession, hostKey = true, relayHooks = {}, endpoints, password } = {}) {
  const keyPair = await generateKeyPair(true);
  const logs = [];
  const probes = { count: 0 };
  const host = createMemoryHost({
    auth: { authorizedKeys: `${await exportPublicKeySSH(keyPair.publicKey)} alice`, ...(password ? { password } : {}) },
    exec: async () => 0,
    hostKey,
    dataStreams: false,
    sealSession,
    endpoints: endpoints ?? {
      [ENDPOINT]: (d) => { d.readable.pipeTo(d.writable).catch(() => {}); },
      probe: (d) => { probes.count += 1; d.destroy(); },
    },
    onLog: (l) => logs.push(l),
  });
  closers.push(() => host.close());
  const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise((r) => wss.once('listening', r));
  wss.on('connection', (ws) => { void host.accept(ws); });
  closers.push(async () => { for (const c of wss.clients) c.terminate(); wss.close(); });
  const relay = await hostileRelay(`ws://127.0.0.1:${wss.address().port}`, relayHooks);
  closers.push(() => relay.close());
  return { host, relay, logs, keyPair, probes };
}

async function login(s, opts = {}) {
  const client = new WshClient();
  closers.push(() => client.disconnect());
  await client.connect(s.relay.url, { username: 'alice', keyPair: s.keyPair, transport: 'ws', ...opts });
  return client;
}

async function echo(client, text) {
  const d = await client.openEndpoint(ENDPOINT);
  const chunks = [];
  const reader = d.readable.getReader();
  const writer = d.writable.getWriter();
  await writer.write(new TextEncoder().encode(text));
  let got = 0;
  while (got < text.length) {
    const { value, done } = await reader.read();
    if (done) break;
    chunks.push(value); got += value.length;
  }
  d.destroy();
  return new TextDecoder().decode(Buffer.concat(chunks));
}

/** Everything the relay saw, as bytes, per direction. */
const wire = (relay) => relay.seen.map((e) => ({ dir: e.dir, type: e.msg.type, bytes: Buffer.from(cborEncode(e.msg)) }));
const hasText = (relay, text) => wire(relay).some((w) => w.bytes.includes(Buffer.from(text)));

describe('the JS client seals a session (sealSession)', () => {
  it('is validated: a value other than false, auto or true is a TypeError', async () => {
    const s = await setup({ sealSession: 'offer' });
    await assert.rejects(login(s, { sealSession: 'yes' }), /sealSession must be/);
    await assert.rejects(login(s, { sealSession: 'offer' }), /sealSession must be/);
  });

  it('control: UNSEALED (false), the relay reads the endpoint name and the data -- what #155 reports', async () => {
    const s = await setup({ sealSession: 'offer' });
    const c = await login(s, { sealSession: false });
    assert.equal(await echo(c, MARKER), MARKER);
    assert.ok(hasText(s.relay, MARKER), 'the relay saw the data');
    assert.ok(hasText(s.relay, ENDPOINT), 'the relay saw the endpoint name');
    assert.equal(c.sessionSealed, false);
  });

  it("'auto' (the default) against a host that only OFFERS does not seal: an old client and a new one behave the same", async () => {
    const s = await setup({ sealSession: 'offer' });
    const c = await login(s); // default
    assert.equal(c.sessionSealed, false);
    assert.equal(await echo(c, MARKER), MARKER);
    assert.ok(hasText(s.relay, MARKER));
  });

  it('true against an offering host: the data comes back intact and the relay sees neither the data nor the endpoint name', async () => {
    const s = await setup({ sealSession: 'offer' });
    const c = await login(s, { sealSession: true });
    assert.equal(c.sessionSealed, true);
    assert.equal(await echo(c, MARKER), MARKER);
    assert.ok(s.logs.some((l) => /session sealed/.test(l)), s.logs.join(' | '));
    assert.ok(!hasText(s.relay, MARKER), 'the data crossed the relay in the clear');
    assert.ok(!hasText(s.relay, ENDPOINT), 'the endpoint name crossed the relay in the clear');
    // After the login, the only plain messages in either direction are the key exchange and the keepalive.
    const authOk = s.relay.seen.findIndex((e) => e.dir === 'to-client' && e.msg.type === MSG.AUTH_OK);
    assert.ok(authOk > 0);
    const after = s.relay.seen.slice(authOk + 1).map((e) => e.msg.type);
    assert.ok(after.length > 4, 'traffic was seen');
    for (const t of after) assert.ok([MSG.KEY_EXCHANGE, MSG.ENCRYPTED_FRAME, MSG.PING, MSG.PONG].includes(t), `a plain message of type ${t} crossed after the login`);
  });

  it("'auto' against a host that REQUIRES sealing seals on its own", async () => {
    const s = await setup({ sealSession: 'require' });
    const c = await login(s);
    assert.equal(c.sessionSealed, true);
    assert.equal(await echo(c, MARKER), MARKER);
    assert.ok(!hasText(s.relay, MARKER));
  });

  it('a host that REQUIRES sealing serves a client that opted out of nothing: false is refused and opens nothing', async () => {
    const s = await setup({ sealSession: 'require' });
    const c = await login(s, { sealSession: false });
    await assert.rejects(c.openEndpoint('probe', { timeoutMs: 1500 }));
    assert.equal(s.probes.count, 0, 'the endpoint was never opened');
  });

  it('true against a host that does not offer it is refused BEFORE a credential leaves the client', async () => {
    const s = await setup({ sealSession: false });
    await assert.rejects(login(s, { sealSession: true }), /does not offer "e2e-session"/);
    const sent = s.relay.seen.filter((e) => e.dir === 'to-relay').map((e) => e.msg.type);
    assert.ok(!sent.includes(MSG.AUTH), 'no AUTH message was sent');
    assert.ok(!sent.includes(MSG.KEY_EXCHANGE), 'no key exchange was sent');
    assert.equal(s.probes.count, 0);
  });

  it('true against a host with no host key is refused (the exchange has nothing to authenticate the host with)', async () => {
    const s = await setup({ sealSession: false, hostKey: false });
    await assert.rejects(login(s, { sealSession: true }), /e2e-session/);
  });

  it('true with a password login is refused with a sentence, and nothing is sent', async () => {
    const s = await setup({ sealSession: 'offer', password: () => true });
    const c = new WshClient();
    closers.push(() => c.disconnect());
    await assert.rejects(c.connect(s.relay.url, { username: 'alice', password: 'x', transport: 'ws', sealSession: true }), /key login/);
    assert.ok(!s.relay.seen.some((e) => e.dir === 'to-relay' && e.msg.type === MSG.AUTH));
  });

  it('a relay that strips the e2e-session features cannot make true talk in the clear (refused before login); auto stays plain, and a requiring host then refuses it', async () => {
    const strip = (m) => (m.type === MSG.SERVER_HELLO ? { ...m, features: (m.features ?? []).filter((f) => !f.startsWith('e2e-session')) } : m);
    const s = await setup({ sealSession: 'require', relayHooks: { toClient: strip } });
    await assert.rejects(login(s, { sealSession: true }), /does not offer "e2e-session"/);
    assert.ok(!s.relay.seen.some((e) => e.dir === 'to-relay' && e.msg.type === MSG.AUTH));
    const s2 = await setup({ sealSession: 'require', relayHooks: { toClient: strip } });
    const c = await login(s2); // auto: it believed the relay, and the host that requires sealing serves it nothing
    assert.equal(c.sessionSealed, false);
    await assert.rejects(c.openEndpoint('probe', { timeoutMs: 1500 }));
    assert.equal(s2.probes.count, 0);
  });

  it('a stream opened by the caller is refused on a sealed session (its bytes would not be frames)', async () => {
    const s = await setup({ sealSession: 'offer' });
    const c = await login(s, { sealSession: true });
    await assert.rejects(c.openStream(), /sealed/);
  });

  it('a large transfer both ways stays intact on a sealed session (credit still works)', async () => {
    const s = await setup({ sealSession: 'offer' });
    const c = await login(s, { sealSession: true });
    const payload = Buffer.alloc(1.5 * 1024 * 1024, 7);
    for (let i = 0; i < payload.length; i += 4099) payload[i] = i & 0xff;
    const d = await c.openEndpoint(ENDPOINT);
    const reader = d.readable.getReader(); const writer = d.writable.getWriter();
    const got = [];
    let total = 0;
    const reading = (async () => { while (total < payload.length) { const { value, done } = await reader.read(); if (done) break; got.push(value); total += value.length; } })();
    for (let i = 0; i < payload.length; i += 16384) await writer.write(payload.subarray(i, i + 16384));
    await reading;
    d.destroy();
    assert.ok(Buffer.concat(got).equals(payload));
  });
});

describe('a hostile relay cannot work with a sealed session', () => {
  it('a flipped bit in a frame toward the host closes the session: nothing is delivered, the host says why', async () => {
    let armed = false;
    const flip = (m) => {
      if (armed && m.type === MSG.ENCRYPTED_FRAME) { armed = false; const ct = new Uint8Array(m.ciphertext); ct[ct.length - 1] ^= 1; return { ...m, ciphertext: ct }; }
      return m;
    };
    const s = await setup({ sealSession: 'offer', relayHooks: { toRelay: (m) => flip(m) } });
    const c = await login(s, { sealSession: true });
    let closed = false; c.onClose = () => { closed = true; };
    assert.equal(await echo(c, 'warm up'), 'warm up');
    armed = true;
    await assert.rejects(c.openEndpoint('probe', { timeoutMs: 3000 }));
    await until(() => s.logs.some((l) => /did not open/.test(l)), `the host to refuse the frame: ${s.logs.join(' | ')}`);
    await until(() => closed, 'the client to learn the session is over');
    assert.equal(s.probes.count, 0);
  });

  it('a flipped bit in a frame toward the client closes the client (a fatal error, not a dropped message)', async () => {
    let armed = false;
    const flip = (m) => {
      if (armed && m.type === MSG.ENCRYPTED_FRAME) { armed = false; const ct = new Uint8Array(m.ciphertext); ct[0] ^= 1; return { ...m, ciphertext: ct }; }
      return m;
    };
    const s = await setup({ sealSession: 'offer', relayHooks: { toClient: (m) => flip(m) } });
    const c = await login(s, { sealSession: true });
    let closed = false; c.onClose = () => { closed = true; };
    const errors = []; c.onError = (e) => errors.push(e);
    assert.equal(await echo(c, 'warm up'), 'warm up');
    armed = true;
    const second = echo(c, MARKER).then((v) => v, () => null);
    await until(() => closed, 'the client to close after a frame that does not open');
    assert.notEqual(await second, MARKER);
    assert.ok(errors.some((e) => /sealed frame did not open/.test(e.message)), errors.map((e) => e.message).join(' | '));
  });

  it('a replayed frame closes the session', async () => {
    let last = null; let replay = false;
    const s = await setup({
      sealSession: 'offer',
      relayHooks: { toRelay: (m, ctx) => { if (m.type === MSG.ENCRYPTED_FRAME) { if (replay) { replay = false; return [m, last]; } last = m; } return m; } },
    });
    const c = await login(s, { sealSession: true });
    assert.equal(await echo(c, 'warm up'), 'warm up');
    replay = true;
    await c.openEndpoint('probe', { timeoutMs: 3000 }).catch(() => {});
    await until(() => s.logs.some((l) => /did not open/.test(l)), `the host to refuse the replay: ${s.logs.join(' | ')}`);
  });

  it('a plain message injected toward the client after the key exchange is not heard, and the session carries on', async () => {
    const s = await setup({ sealSession: 'offer' });
    const c = await login(s, { sealSession: true });
    let closed = false; c.onClose = () => { closed = true; };
    assert.equal(await echo(c, 'hi'), 'hi');
    s.relay.context().injectToClient({ type: MSG.SHUTDOWN, reason: 'injected by the relay' });
    s.relay.context().injectToClient({ type: MSG.ERROR, code: 9, message: 'injected by the relay' });
    await sleep(300);
    assert.equal(closed, false, 'a plain Shutdown did not close the client');
    assert.equal(await echo(c, 'still up'), 'still up');
  });

  it('a plain message heard on a sealed session is counted and reported to onDrop, never written to the console', async () => {
    const s = await setup({ sealSession: 'offer' });
    const c = await login(s, { sealSession: true });
    assert.deepEqual(c.droppedMessages, { plaintext: 0, unopened: 0 });
    const drops = [];
    c.onDrop = (d) => drops.push(d);
    const written = [];
    const real = { warn: console.warn, error: console.error };
    console.warn = (...a) => written.push(a.join(' '));
    console.error = (...a) => written.push(a.join(' '));
    try {
      assert.equal(await echo(c, 'hi'), 'hi');
      s.relay.context().injectToClient({ type: MSG.SHUTDOWN, reason: 'injected by the relay' });
      s.relay.context().injectToClient({ type: MSG.ERROR, code: 9, message: 'injected by the relay' });
      await until(() => c.droppedMessages.plaintext === 2, 'both injected messages to be counted');
      assert.equal(await echo(c, 'still up'), 'still up');
    } finally { Object.assign(console, real); }
    assert.deepEqual(c.droppedMessages, { plaintext: 2, unopened: 0 });
    assert.deepEqual(drops.map((d) => [d.reason, d.messageType]), [['plaintext-on-sealed-session', MSG.SHUTDOWN], ['plaintext-on-sealed-session', MSG.ERROR]]);
    assert.deepEqual(written.filter((l) => /wsh:client/.test(l)), [], 'nothing on the console by default');
  });

  it('a throwing onDrop handler does not change what the client does', async () => {
    const s = await setup({ sealSession: 'offer' });
    const c = await login(s, { sealSession: true });
    c.onDrop = () => { throw new Error('handler bug'); };
    s.relay.context().injectToClient({ type: MSG.SHUTDOWN, reason: 'injected by the relay' });
    await until(() => c.droppedMessages.plaintext === 1, 'the drop to be counted');
    assert.equal(await echo(c, 'still up'), 'still up');
  });

  it('a plain message injected toward the host after the key exchange is not heard', async () => {
    const s = await setup({ sealSession: 'offer' });
    const c = await login(s, { sealSession: true });
    assert.equal(await echo(c, 'hi'), 'hi');
    await s.relay.context().injectToRelay({ type: MSG.OPEN_ENDPOINT, gateway_id: 99, name: 'probe' });
    await sleep(300);
    assert.equal(s.probes.count, 0);
    assert.ok(s.logs.some((l) => /plaintext message/.test(l)));
    assert.equal(await echo(c, 'still up'), 'still up');
  });

  it('a relay that answers the key exchange with a key of its own is refused: the host key signs it', async () => {
    // A man in the middle that terminates the exchange: it drops the host's reply and the client gets nothing it can verify.
    const s = await setup({ sealSession: 'offer', relayHooks: { toClient: (m) => (m.type === MSG.KEY_EXCHANGE ? { ...m, signature: new Uint8Array(64) } : m) } });
    await assert.rejects(login(s, { sealSession: true, timeout: 3000 }), /does not verify|did not sign|E2E_PEER/);
    assert.equal(s.probes.count, 0);
  });

  it('a host key that differs from the pinned one is refused before sealing', async () => {
    const s = await setup({ sealSession: 'offer' });
    const other = await setup({ sealSession: 'offer' });
    const hk = await (async () => { const c = new WshClient(); await c.connect(other.relay.url, { username: 'alice', keyPair: other.keyPair, transport: 'ws', trustOnFirstUse: false, onHostKey: () => true }); const k = c.hostKey; await c.disconnect(); return k; })();
    await assert.rejects(login(s, { sealSession: true, expectHostKey: hk.fingerprint }), /host key mismatch/i);
  });
});
