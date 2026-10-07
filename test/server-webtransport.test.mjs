// test/server-webtransport.test.mjs -- the WebTransport listener of `@johnhenry/wsh/server` (#70),
// driven by the stock client over a real HTTP/3 connection to https://127.0.0.1:<port>, pinning the
// server's self-signed certificate by hash (`serverCertificateHashes`).
//
// Needs the optional native packages (@fails-components/webtransport and its quiche transport); where
// the binary is unavailable these tests are skipped with the reason, not failed.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { X509Certificate, createHash } from 'node:crypto';
import { createWshServer } from '@johnhenry/wsh/server';
import { WshClient, generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';
import { generateSelfSignedCertificate, MAX_PINNED_CERT_DAYS } from '../src/server/self-signed.mjs';

const dec = new TextDecoder();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let wtLib = null;
let skipReason = false;
try {
  wtLib = await import('@fails-components/webtransport');
  await wtLib.quicheLoaded;
  // Prove the native transport really runs here, not merely imports.
  const probe = generateSelfSignedCertificate();
  const s = new wtLib.Http3Server({ port: 0, host: '127.0.0.1', secret: 'probe', cert: probe.cert, privKey: probe.privKey });
  s.startServer();
  await s.ready;
  s.stopServer();
} catch (err) {
  skipReason = `the native WebTransport packages are unavailable (${String(err?.message ?? err).split('\n')[0]})`;
}

describe('self-signed certificate', () => {
  it('is ECDSA P-256, valid for no more than 14 days, and its SHA-256 is the DER hash', () => {
    const c = generateSelfSignedCertificate();
    const x = new X509Certificate(c.cert);
    assert.equal(x.publicKey.asymmetricKeyType, 'ec');
    assert.equal(x.publicKey.asymmetricKeyDetails.namedCurve, 'prime256v1');
    const days = (new Date(x.validTo) - new Date(x.validFrom)) / 86_400_000;
    assert.ok(days > 0 && days <= MAX_PINNED_CERT_DAYS, `validity ${days} days`);
    assert.ok(new Date(x.validFrom) <= new Date() && new Date(x.validTo) > new Date());
    assert.equal(c.hashHex, createHash('sha256').update(x.raw).digest('hex'));
    assert.deepEqual([...c.hash], [...Buffer.from(c.hashHex, 'hex')]);
    assert.ok(x.verify(x.publicKey), 'self-signature verifies');
    assert.ok(x.checkIP('127.0.0.1') && x.checkHost('localhost'));
    assert.equal(c.privKey.includes('BEGIN PRIVATE KEY'), true);
  });

  it('refuses a validity a browser would refuse, and takes a custom host list', () => {
    assert.throws(() => generateSelfSignedCertificate({ validityDays: 15 }), /validityDays/);
    assert.throws(() => generateSelfSignedCertificate({ validityDays: 0 }), /validityDays/);
    const x = new X509Certificate(generateSelfSignedCertificate({ hosts: ['example.test', '10.1.2.3', '2001:db8::1'], validityDays: 14 }).cert);
    assert.ok(x.checkHost('example.test') && x.checkIP('10.1.2.3'));
    assert.ok(/2001:db8:0:0:0:0:0:1/i.test(x.subjectAltName), x.subjectAltName);
  });

  it('is different every time', () => {
    assert.notEqual(generateSelfSignedCertificate().hashHex, generateSelfSignedCertificate().hashHex);
  });
});

describe('WebTransport listener', { skip: skipReason }, () => {
  let keyPair; let otherKey; let authorizedKeys; let root; let server; let wt; let savedWT;

  before(async () => {
    keyPair = await generateKeyPair(true);
    otherKey = await generateKeyPair(true);
    authorizedKeys = `${await exportPublicKeySSH(keyPair.publicKey)} alice\n`;
    root = await mkdtemp(path.join(tmpdir(), 'wsh-wt-'));
    await writeFile(path.join(root, 'a.txt'), 'hello file');
    server = createWshServer({
      auth: { authorizedKeys }, exec: true, fs: { root },
      mcp: { tools: [{ name: 'add', description: 'a+b', inputSchema: { type: 'object', properties: { a: { type: 'number' }, b: { type: 'number' } }, required: ['a', 'b'] }, call: ({ a, b }) => a + b }] },
      webTransport: { selfSigned: true },
    });
    await server.listen();
    wt = server.webTransport();
    // Node has no WebTransport global; the stock client uses the platform one, so install the library's.
    savedWT = globalThis.WebTransport;
    globalThis.WebTransport = wtLib.WebTransport;
  });
  after(async () => {
    globalThis.WebTransport = savedWT;
    await server?.close();
    await rm(root, { recursive: true, force: true });
  });

  const clients = [];
  async function connect(hash = wt.certificateHash, key = keyPair, url = wt.url) {
    const client = new WshClient();
    await client.connect(url, {
      username: 'alice', keyPair: key, transport: 'wt',
      webTransport: { serverCertificateHashes: [{ algorithm: 'sha-256', value: hash }] },
    });
    clients.push(client);
    return client;
  }
  const collect = (session) => new Promise((resolve) => {
    const chunks = [];
    let code;
    session.onData = (d) => chunks.push(d);
    session.onExit = (c) => { code = c; };
    session.onClose = () => resolve({ out: dec.decode(Buffer.concat(chunks)), code });
  });

  it('exposes the bound address and the certificate hash to pin', () => {
    assert.match(wt.url, /^https:\/\/127\.0\.0\.1:\d+\/wsh$/);
    assert.equal(wt.path, '/wsh');
    assert.equal(wt.certificateHash.length, 32);
    assert.equal(wt.certificateHashHex.length, 64);
    assert.ok(wt.notAfter > new Date() && wt.notAfter - new Date() <= MAX_PINNED_CERT_DAYS * 86_400_000);
  });

  it('the stock client connects over https:// with a pinned hash and runs `echo hello`', async () => {
    const client = await connect();
    assert.ok(client.hasFeature('stream-announce'), 'a WebTransport stream is visible as soon as it is opened: no primer');
    const session = await client.openSession({ type: 'exec', command: 'echo hello' });
    const { out, code } = await collect(session);
    assert.equal(out, 'hello\n');
    assert.equal(code, 0);
    await client.disconnect();
  });

  it('concurrent exec sessions each get their own stream and output', async () => {
    const client = await connect();
    const sessions = await Promise.all(Array.from({ length: 6 }, (_, i) => client.openSession({ type: 'exec', command: `sleep 0.0${i}; echo session-${i}; echo err-${i} >&2; exit ${i}` })));
    const results = await Promise.all(sessions.map(collect));
    results.forEach((r, i) => {
      assert.equal(r.out.split('\n').filter(Boolean).sort().join(','), `err-${i},session-${i}`);
      assert.equal(r.code, i);
    });
    await client.disconnect();
  });

  it('stdin reaches the process over its data stream', async () => {
    const client = await connect();
    const session = await client.openSession({ type: 'exec', command: 'read x; echo "got:$x"' });
    const done = collect(session);
    await session.write('abc\n');
    assert.equal((await done).out, 'got:abc\n');
    await client.disconnect();
  });

  it('fileWrite and fileRename round-trip', async () => {
    const client = await connect();
    assert.ok(client.hasFeature('file-write') && client.hasFeature('file-rename'));
    assert.equal((await client.fileWrite('note.txt', 'first draft')).success, true);
    assert.equal(await readFile(path.join(root, 'note.txt'), 'utf8'), 'first draft');
    assert.equal((await client.fileRename('note.txt', 'final.txt')).success, true);
    assert.equal(await readFile(path.join(root, 'final.txt'), 'utf8'), 'first draft');
    const st = await client.fileStat('a.txt');
    assert.equal(st.metadata.size, 10);
    const big = Buffer.alloc(300_000, 7);
    await client.upload(big, 'big.bin');
    assert.deepEqual(Buffer.from(await client.download('big.bin')), big);
    await client.disconnect();
  });

  it('MCP tools work on this transport too', async () => {
    const client = await connect();
    assert.equal(await client.callTool('add', { a: 2, b: 3 }), 5);
    const [x, y] = await Promise.all([client.callTool('add', { a: 1, b: 1 }), client.callTool('add', { a: 5, b: 5 })]);
    assert.deepEqual([x, y], [2, 10]);
    await client.disconnect();
  });

  it('authentication still applies: an unlisted key is refused', async () => {
    await assert.rejects(() => connect(wt.certificateHash, otherKey), /auth|not authorized|AUTH/i);
  });

  it('a client that pins a different certificate does not connect', async () => {
    await assert.rejects(() => connect(createHash('sha256').update('not the cert').digest()), Error);
  });

  it('a path nothing is registered on is not served', async () => {
    await assert.rejects(() => connect(wt.certificateHash, keyPair, wt.url.replace('/wsh', '/elsewhere')), Error);
  });

  it('a session ends with its client: the process it started is killed', async () => {
    const client = await connect();
    const session = await client.openSession({ type: 'exec', command: 'echo pid:$$; exec sleep 30' });
    let text = '';
    session.onData = (d) => { text += dec.decode(d); };
    for (let i = 0; i < 200 && !text.includes('pid:'); i++) await sleep(10);
    const pid = Number(/pid:(\d+)/.exec(text)[1]);
    await client.disconnect();
    let alive = true;
    for (let i = 0; i < 200 && alive; i++) { await sleep(10); try { process.kill(pid, 0); } catch { alive = false; } }
    assert.equal(alive, false);
  });

  it('serves a certificate you supply, and the WebSocket listener keeps working alongside', async () => {
    const own = generateSelfSignedCertificate({ validityDays: 3 });
    const both = createWshServer({ auth: { authorizedKeys }, exec: true, webTransport: { cert: own.cert, privKey: own.privKey, path: '/custom' } });
    const { port } = await both.listen();
    try {
      const w = both.webTransport();
      assert.equal(w.certificateHash, null, 'no hash is claimed for a certificate it did not make');
      assert.ok(w.url.endsWith('/custom'));
      const viaWt = await connect(own.hash, keyPair, w.url);
      assert.equal((await collect(await viaWt.openSession({ type: 'exec', command: 'echo wt' }))).out, 'wt\n');
      const ws = new WshClient();
      await ws.connect(`ws://127.0.0.1:${port}`, { username: 'alice', keyPair });
      assert.equal((await collect(await ws.openSession({ type: 'exec', command: 'echo ws' }))).out, 'ws\n');
      await ws.disconnect();
    } finally { await both.close(); }
  });

  it('refuses a configuration that cannot work, with a clear message', async () => {
    await assert.rejects(() => createWshServer({ webTransport: {} }).listen(), /cert and privKey|selfSigned/);
    await assert.rejects(() => createWshServer({ webTransport: { selfSigned: true, cert: 'x', privKey: 'y' } }).listen(), /either selfSigned or cert/);
    await assert.rejects(() => createWshServer({ webTransport: { selfSigned: true, path: 'nope' } }).listen(), /must start with "\/"/);
  });

  it('close() stops the listener', async () => {
    const s = createWshServer({ auth: { authorizedKeys }, exec: true, webTransport: { selfSigned: true } });
    await s.listen();
    const w = s.webTransport();
    const client = await connect(w.certificateHash, keyPair, w.url);
    await s.close();
    assert.equal(s.webTransport(), null);
    await sleep(300);
    assert.notEqual(client.state, 'authenticated');
  });
});

describe('WebTransport without the native packages', () => {
  it('the server stays importable and WebSocket-only servers never touch them', async () => {
    const s = createWshServer({});
    await s.listen();
    assert.equal(s.webTransport(), null);
    await s.close();
  });
});
