// test/server-relay.test.mjs -- relay / reverse mode of `@johnhenry/wsh/server` (#69),
// driven by two stock clients: a peer registers, an operator lists, connects and runs a
// command through the bridge.
import { describe, it, before, after, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createWshServer, createReverseHost } from '@johnhenry/wsh/server';
import {
  WshClient, generateKeyPair, exportPublicKeySSH, exportPublicKeyRaw, fingerprint, signPeerRecord,
  reverseRegister, relayForward, cborEncode, MSG, open as openMsg, ping as pingMsg,
} from '@johnhenry/wsh';

const dec = new TextDecoder();
const relayFeaturesHave = (client, name) => client.serverFeatures.includes(name);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(cond, what, ms = 4000) {
  const t0 = Date.now();
  for (;;) {
    const v = await cond();
    if (v) return v;
    if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`);
    await sleep(10);
  }
}

describe('relay / reverse mode', () => {
  const keys = {};
  let authorizedKeys;
  const servers = [];
  const clients = [];
  const hosts = [];

  before(async () => {
    for (const name of ['host', 'bob', 'carol', 'mallory']) {
      const keyPair = await generateKeyPair(true);
      keys[name] = { keyPair, fp: await fingerprint(await exportPublicKeyRaw(keyPair.publicKey)) };
    }
    authorizedKeys = (await Promise.all(Object.entries(keys).map(async ([n, k]) => `${await exportPublicKeySSH(k.keyPair.publicKey)} ${n}`))).join('\n');
  });
  afterEach(async () => {
    for (const h of hosts.splice(0)) await h.close();
    for (const c of clients.splice(0)) await c.disconnect().catch(() => {});
    for (const s of servers.splice(0)) await s.close();
  });

  const POLICY = {
    canRegister: (who) => who.username === 'host',
    canConnect: (from) => from.username === 'bob',
  };
  const logs = [];
  let relayServer = null;
  async function startRelay(relay = POLICY, extra = {}) {
    const server = createWshServer({ auth: { authorizedKeys }, relay, onLog: (l) => logs.push(l), ...extra });
    const { port } = await server.listen();
    servers.push(server);
    relayServer = server;
    return `ws://127.0.0.1:${port}`;
  }
  /** Registration has no ack on the wire: wait until the relay has the peer. */
  const registered = (fp = keys.host.fp) => until(() => relayServer.peerFingerprints().includes(fp), 'the peer to register');
  async function login(url, name) {
    const c = new WshClient();
    await c.connect(url, { username: name, keyPair: keys[name].keyPair });
    clients.push(c);
    return c;
  }
  async function startHost(url, opts = {}) {
    const host = createReverseHost({
      url, username: 'host', keyPair: keys.host.keyPair, exec: true,
      accept: (op) => op.fingerprint === keys.bob.fp, reconnect: false, ...opts,
    });
    await host.start();
    hosts.push(host);
    await registered();
    return host;
  }
  /** A stock-client peer that registers and then does what the test says. */
  async function stockPeer(url, name = 'host', expose = { exec: true }) {
    const c = new WshClient();
    await c.connectReverse(url, { username: name, keyPair: keys[name].keyPair, expose });
    clients.push(c);
    await registered(keys[name].fp);
    return c;
  }
  const runOnce = (session) => new Promise((resolve) => {
    const chunks = [];
    let code;
    session.onData = (d) => chunks.push(d);
    session.onExit = (c) => { code = c; };
    session.onClose = () => resolve({ out: dec.decode(Buffer.concat(chunks)), code });
  });

  it('A registers exposing exec; B lists, connects and runs `echo hello` through the bridge', async () => {
    const url = await startRelay();
    const host = await startHost(url);
    const bob = await login(url, 'bob');

    const peers = await bob.listPeers();
    assert.equal(peers.length, 1);
    assert.equal(peers[0].fingerprint, keys.host.fp);
    assert.equal(peers[0].username, 'host');
    assert.ok(peers[0].capabilities.includes('exec'));
    assert.equal(peers[0].verified, true, "the peer's own signed record verifies on the operator's side");

    const accepted = await bob.reverseConnect(peers[0].fingerprint);
    assert.equal(accepted.type, MSG.REVERSE_ACCEPT);
    const session = await bob.openSession({ type: 'exec', command: 'echo hello; echo oops >&2; exit 3' });
    assert.equal(session.dataMode, 'virtual', 'no client-opened streams cross a relay');
    const { out, code } = await runOnce(session);
    assert.equal(out, 'hello\noops\n');
    assert.equal(code, 3);
    assert.equal(host.connected, true);
  });

  it('stdin and signals cross the bridge; the command runs as the operator the relay authenticated', async () => {
    const url = await start();
    async function start() { return startRelay(); }
    await startHost(url, { exec: async (command, io) => { io.onInput((d) => { io.write(`${io.user}:${dec.decode(d)}`); }); await new Promise((r) => io.signal.addEventListener('abort', r)); return 0; } });
    const bob = await login(url, 'bob');
    await bob.reverseConnect(keys.host.fp);
    const session = await bob.openSession({ type: 'exec', command: 'anything' });
    const got = new Promise((r) => { session.onData = (d) => r(dec.decode(d)); });
    await session.write('ping');
    assert.equal(await got, 'bob:ping');
    const closed = new Promise((r) => { session.onClose = r; });
    await session.signal?.('TERM');
    await closed;
  });

  it('fs and MCP tools are served through the bridge too', async () => {
    const root = await mkdtemp(path.join(tmpdir(), 'wsh-relay-'));
    try {
      await writeFile(path.join(root, 'a.txt'), 'hello file');
      const url = await startRelay();
      await startHost(url, { exec: undefined, fs: { root }, mcp: { tools: [{ name: 'add', description: 'a+b', inputSchema: { type: 'object', properties: { a: { type: 'number' }, b: { type: 'number' } }, required: ['a', 'b'] }, call: ({ a, b }) => a + b }] } });
      const bob = await login(url, 'bob');
      const [peer] = await bob.listPeers();
      assert.deepEqual(peer.capabilities.sort(), ['fs', 'tools']);
      await bob.reverseConnect(peer.fingerprint);
      assert.equal((await bob.fileStat('a.txt')).success, true);
      assert.equal(dec.decode((await bob.fileRead('a.txt', 6, 4)).metadata.data), 'file');
      assert.deepEqual((await bob.fileList('/')).entries.map((e) => e.name), ['a.txt']);
      // fileWrite()/fileRename() are gated on the features of the host behind the bridge (it states them in
      // ReverseAccept.features), not on the relay's ServerHello, which has no `fs` here (#80).
      assert.equal(relayFeaturesHave(bob, 'file-write'), false, 'the relay itself has no fs');
      assert.equal(bob.hasFeature('file-write'), true, 'the bridged host does');
      assert.ok(bob.bridgedFeatures.includes('file-rename'));
      assert.equal((await bob.fileWrite('b.txt', 'x')).success, true);
      assert.equal((await bob.fileRename('b.txt', 'c.txt')).success, true);
      assert.equal(await readFile(path.join(root, 'c.txt'), 'utf8'), 'x');
      assert.deepEqual((await bob.discoverTools()).map((t) => t.name), ['add']);
      assert.equal(await bob.callTool('add', { a: 2, b: 3 }), 5);
      assert.match((await bob.callTool('add', { a: 'x' })).error, /invalid arguments/);
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  describe('default deny', () => {
    it('with no policy nobody can register, list or connect', async () => {
      const url = await startRelay({});
      const peer = new WshClient();
      const errors = [];
      peer.onError = (e) => errors.push(e.message);
      await peer.connectReverse(url, { username: 'host', keyPair: keys.host.keyPair, expose: { exec: true } });
      clients.push(peer);
      await until(() => errors.some((m) => /registration refused: registration not permitted/.test(m)), 'a refusal');
      const bob = await login(url, 'bob');
      assert.deepEqual(await bob.listPeers(), []);
      const r = await bob.reverseConnect(keys.host.fp);
      assert.equal(r.type, MSG.REVERSE_REJECT);
      assert.equal(r.reason, 'no such peer');
    });

    it('canRegister decides who may be a peer', async () => {
      const url = await startRelay();
      const errors = [];
      const mallory = new WshClient();
      mallory.onError = (e) => errors.push(e.message);
      await mallory.connectReverse(url, { username: 'mallory', keyPair: keys.mallory.keyPair });
      clients.push(mallory);
      await until(() => errors.length > 0, 'refusal');
      assert.deepEqual(await (await login(url, 'bob')).listPeers(), []);
    });

    it('canConnect decides who sees and reaches a peer; unreachable looks the same as absent', async () => {
      const url = await startRelay();
      await startHost(url);
      const carol = await login(url, 'carol');
      assert.deepEqual(await carol.listPeers(), [], 'a peer carol could not connect to is not listed');
      const r = await carol.reverseConnect(keys.host.fp);
      assert.equal(r.type, MSG.REVERSE_REJECT);
      assert.equal(r.reason, 'no such peer');
      const missing = await carol.reverseConnect('ab'.repeat(32));
      assert.equal(missing.reason, r.reason);
    });

    it('the peer has its own say: accept defaults to refusing, and can refuse a specific operator', async () => {
      const url = await startRelay({ ...POLICY, canConnect: () => true });
      await startHost(url, { accept: undefined });
      const bob = await login(url, 'bob');
      assert.equal((await bob.reverseConnect(keys.host.fp)).reason, 'not accepted');
      await hosts.pop().close();
      await startHost(url, { accept: (op) => op.username === 'nobody' });
      assert.equal((await bob.reverseConnect(keys.host.fp)).reason, 'not accepted');
    });

    it('a server without `relay` answers instead of leaving the operator to time out', async () => {
      const server = createWshServer({ auth: { authorizedKeys } });
      const { port } = await server.listen();
      servers.push(server);
      const bob = await login(`ws://127.0.0.1:${port}`, 'bob');
      assert.deepEqual(await bob.listPeers(), []);
      const r = await bob.reverseConnect(keys.host.fp);
      assert.equal(r.type, MSG.REVERSE_REJECT);
      assert.match(r.reason, /not enabled/);
    });

    it('relay operations need a key login', async () => {
      const server = createWshServer({ auth: { password: (u, p) => p === 'pw', authorizedKeys }, relay: { canRegister: () => true, canConnect: () => true } });
      const { port } = await server.listen();
      servers.push(server);
      const c = new WshClient();
      const errors = [];
      c.onError = (e) => errors.push(e.message);
      await c.connect(`ws://127.0.0.1:${port}`, { username: 'host', password: 'pw' });
      clients.push(c);
      await c.sendControl(reverseRegister({ username: 'host', publicKey: new Uint8Array(32), seq: 1, recordSignature: new Uint8Array(64) }));
      await until(() => errors.some((m) => /key login/.test(m)), 'refusal');
    });
  });

  describe('identity on the wire', () => {
    /** An operator bridged to a stock-client peer that records what reaches it. */
    async function bridged() {
      const url = await startRelay();
      const peer = await stockPeer(url);
      const received = [];
      peer.onReverseConnect = async (req) => {
        peer.trustRelayPeer(req.from_fingerprint);
        received.push({ connectFrom: req.from_fingerprint, connectUser: req.username });
        await peer.sendRelayControl({ type: MSG.REVERSE_ACCEPT, target_fingerprint: keys.host.fp, username: 'host' });
      };
      peer.onRelayMessage = (m) => received.push(m);
      const bob = await login(url, 'bob');
      return { url, peer, bob, received };
    }

    it('ReverseConnect reaches the peer with the operator\'s authenticated identity, whatever the client wrote', async () => {
      const { bob, received } = await bridged();
      await bob.sendControl({ type: MSG.REVERSE_CONNECT, target_fingerprint: keys.host.fp, username: 'root', from_fingerprint: 'f'.repeat(64) });
      await until(() => received.length > 0, 'ReverseConnect');
      assert.deepEqual(received[0], { connectFrom: keys.bob.fp, connectUser: 'bob' });
    });

    it('a forged from_fingerprint on a client-written RelayForward is replaced by the sender\'s real one', async () => {
      const { bob, received } = await bridged();
      await bob.reverseConnect(keys.host.fp);
      // The peer trusts only bob. A forwarded frame claiming to be from someone else would be dropped by the
      // peer's own gate -- it arrives only because the relay re-stamped it with bob's authenticated key.
      await bob.sendControl(relayForward({ fromFingerprint: keys.carol.fp, inner: cborEncode(openMsg({ kind: 'exec', command: 'echo forged' })) }));
      await until(() => received.some((m) => m.type === MSG.OPEN), 'the forwarded Open');
      assert.equal(received.find((m) => m.type === MSG.OPEN).command, 'echo forged');
    });

    it('a plain forwardable message is wrapped and delivered; a non-forwardable inner is dropped by the relay', async () => {
      const { bob, received } = await bridged();
      await bob.reverseConnect(keys.host.fp);
      logs.length = 0;
      await bob.sendControl(relayForward({ fromFingerprint: 'x', inner: cborEncode(pingMsg({ id: 1 })) }));
      await bob.sendControl(relayForward({ fromFingerprint: 'x', inner: new Uint8Array([0xff, 0xff]) }));
      await bob.sendControl(openMsg({ kind: 'exec', command: 'echo plain' }));
      await until(() => received.some((m) => m.type === MSG.OPEN), 'the plain Open');
      assert.ok(!received.some((m) => m.type === MSG.PING));
      assert.ok(logs.filter((l) => /dropped a RelayForward wrapping a non-forwardable type/.test(l)).length >= 2, 'the relay dropped the Ping and the garbage');
    });

    it('traffic from a connection that is not bridged is never forwarded', async () => {
      const { url, received } = await bridged();
      const carol = await login(url, 'carol');
      await carol.sendControl(relayForward({ fromFingerprint: keys.bob.fp, inner: cborEncode(openMsg({ kind: 'exec', command: 'echo no' })) }));
      await carol.sendControl(openMsg({ kind: 'exec', command: 'echo no' }));
      await sleep(200);
      assert.deepEqual(received, []);
    });

    it('the peer\'s ReverseAccept is attributed to the peer that sent it', async () => {
      const url = await startRelay();
      const peer = await stockPeer(url);
      peer.onReverseConnect = async (req) => {
        peer.trustRelayPeer(req.from_fingerprint);
        await peer.sendRelayControl({ type: MSG.REVERSE_ACCEPT, target_fingerprint: 'e'.repeat(64), username: 'host' });
      };
      const bob = await login(url, 'bob');
      const r = await bob.reverseConnect(keys.host.fp);
      assert.equal(r.target_fingerprint, keys.host.fp);
    });
  });

  describe('signed peer records', () => {
    const record = (extra = {}) => ({ username: 'host', capabilities: ['exec'], peerType: 'host', shellBackend: 'pty', supportsAttach: false, supportsReplay: false, supportsEcho: false, supportsTermSync: false, seq: 1000, ...extra });
    async function register(client, key, rec, { publicKey, signWith } = {}) {
      const { signature, publicKeyRaw } = await signPeerRecord((signWith ?? key).privateKey, (signWith ?? key).publicKey, rec);
      await client.sendControl(reverseRegister({ ...rec, publicKey: publicKey ?? publicKeyRaw, recordSignature: signature }));
    }
    async function rawPeer(url, errors = []) {
      const c = new WshClient();
      c.onError = (e) => errors.push(e.message);
      await c.connect(url, { username: 'host', keyPair: keys.host.keyPair });
      clients.push(c);
      return c;
    }

    it('a record with a stale seq is refused and the newer one stays', async () => {
      const url = await startRelay();
      const errors = [];
      const peer = await rawPeer(url, errors);
      await register(peer, keys.host.keyPair, record({ seq: 2000, capabilities: ['exec', 'fs'] }));
      const bob = await login(url, 'bob');
      await until(async () => (await bob.listPeers()).length === 1, 'registration');
      await register(peer, keys.host.keyPair, record({ seq: 1000, capabilities: ['shell'] }));
      await register(peer, keys.host.keyPair, record({ seq: 2000, capabilities: ['shell'] }));
      await until(() => errors.length >= 2, 'two refusals');
      assert.ok(errors.every((m) => /stale record/.test(m)));
      const [p] = await bob.listPeers();
      assert.equal(p.seq, 2000);
      assert.deepEqual(p.capabilities, ['exec', 'fs']);
      // A newer record replaces it.
      await register(peer, keys.host.keyPair, record({ seq: 3000, capabilities: ['shell'] }));
      await until(async () => (await bob.listPeers())[0].seq === 3000, 'the update');
    });

    it('seq is remembered across a reconnect, so a replayed older record cannot regress a peer', async () => {
      const url = await startRelay();
      const errors = [];
      const first = await rawPeer(url);
      await register(first, keys.host.keyPair, record({ seq: 5000 }));
      const bob = await login(url, 'bob');
      await until(async () => (await bob.listPeers()).length === 1, 'registration');
      await first.disconnect();
      await until(async () => (await bob.listPeers()).length === 0, 'the peer leaving');
      const second = await rawPeer(url, errors);
      await register(second, keys.host.keyPair, record({ seq: 4999 }));
      await until(() => errors.length > 0, 'refusal');
      assert.match(errors[0], /stale record/);
      assert.deepEqual(await bob.listPeers(), []);
    });

    it('a record naming someone else\'s public key, or signed by another key, or tampered with, is refused', async () => {
      const url = await startRelay();
      const errors = [];
      const peer = await rawPeer(url, errors);
      const otherRaw = await exportPublicKeyRaw(keys.mallory.keyPair.publicKey);
      await register(peer, keys.host.keyPair, record(), { publicKey: otherRaw });                       // not the connection's key
      await register(peer, keys.host.keyPair, record(), { signWith: keys.mallory.keyPair, publicKey: await exportPublicKeyRaw(keys.host.keyPair.publicKey) }); // not signed by it
      const { signature, publicKeyRaw } = await signPeerRecord(keys.host.keyPair.privateKey, keys.host.keyPair.publicKey, record());
      await peer.sendControl(reverseRegister({ ...record({ capabilities: ['exec', 'shell'] }), publicKey: publicKeyRaw, recordSignature: signature })); // fields changed after signing
      await until(() => errors.length >= 3, 'three refusals');
      assert.match(errors[0], /does not match the authenticated identity/);
      assert.match(errors[1], /signature does not verify/);
      assert.match(errors[2], /signature does not verify/);
      assert.deepEqual(await (await login(url, 'bob')).listPeers(), []);
    });
  });

  describe('bridges', () => {
    it('one operator per peer at a time; a second is told it is busy', async () => {
      const url = await startRelay({ ...POLICY, canConnect: () => true });
      await startHost(url, { accept: () => true });
      const bob = await login(url, 'bob');
      await bob.reverseConnect(keys.host.fp);
      const carol = await login(url, 'carol');
      assert.match((await carol.reverseConnect(keys.host.fp)).reason, /^busy: this peer already has an operator/);
    });

    it('a ReverseConnect to a peer that never answers is rejected after connectTimeoutMs', async () => {
      const url = await startRelay({ ...POLICY, connectTimeoutMs: 150 });
      await stockPeer(url);                                  // registers, never handles ReverseConnect
      const bob = await login(url, 'bob');
      assert.equal((await bob.reverseConnect(keys.host.fp)).reason, 'peer did not respond');
      // and the peer is free again
      assert.equal((await bob.reverseConnect(keys.host.fp)).reason, 'peer did not respond');
    });

    it('a peer that disconnects mid-request rejects the operator', async () => {
      const url = await startRelay();
      const peer = await stockPeer(url);
      const bob = await login(url, 'bob');
      const pending = bob.reverseConnect(keys.host.fp);
      await sleep(50);
      await peer.disconnect();
      assert.equal((await pending).reason, 'peer went away');
    });

    it('an operator can connect by a unique fingerprint prefix', async () => {
      const url = await startRelay();
      await startHost(url);
      const bob = await login(url, 'bob');
      assert.equal((await bob.reverseConnect(keys.host.fp.slice(0, 12))).type, MSG.REVERSE_ACCEPT);
    });

    it('ending a bridge ends both ends: the operator leaving closes the peer and kills what it was running', async () => {
      const url = await startRelay();
      let started = false;
      let aborted = false;
      const host = await startHost(url, {
        exec: async (cmd, io) => {
          started = true;
          await new Promise((r) => io.signal.addEventListener('abort', () => { aborted = true; r(); }));
          return 143;
        },
      });
      const bob = await login(url, 'bob');
      await bob.reverseConnect(keys.host.fp);
      await bob.openSession({ type: 'exec', command: 'long' });
      await until(() => started, 'the command starting');
      await bob.disconnect();
      await until(() => aborted, 'the command being aborted');
      await until(() => !host.connected, 'the peer leaving the relay');
      assert.deepEqual(relayServer.peerFingerprints(), []);
    });

    it('with reconnect, the host re-registers after a bridge ends and serves the next operator', async () => {
      const url = await startRelay({ ...POLICY, canConnect: () => true });
      await startHost(url, { reconnect: true, accept: () => true });
      const bob = await login(url, 'bob');
      await bob.reverseConnect(keys.host.fp);
      assert.equal((await runOnce(await bob.openSession({ type: 'exec', command: 'echo one' }))).out, 'one\n');
      await bob.disconnect();
      const carol = await login(url, 'carol');
      await until(async () => (await carol.listPeers()).length === 1, 're-registration', 6000);
      assert.equal((await carol.reverseConnect(keys.host.fp)).type, MSG.REVERSE_ACCEPT);
      const { out } = await runOnce(await carol.openSession({ type: 'exec', command: 'echo two' }));
      assert.equal(out, 'two\n');
    });

    it('closing the relay closes bridges and forgets peers', async () => {
      const url = await startRelay();
      const host = await startHost(url, { reconnect: false });
      const bob = await login(url, 'bob');
      await bob.reverseConnect(keys.host.fp);
      await servers.pop().close();
      await until(() => !host.connected, 'the host noticing');
    });
  });
});
