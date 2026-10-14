// test/client-signer.test.mjs -- WshClient signs with a page-held signer ({ publicKey, sign }) instead of a CryptoKeyPair (#100).
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createWshServer } from '@johnhenry/wsh/server';
import {
  WshClient, generateKeyPair, exportPublicKeyRaw, exportPublicKeySSH, sign,
} from '@johnhenry/wsh';

const dec = new TextDecoder();

describe('WshClient signer option (#100)', () => {
  let keyPair; let raw; let server; let url; let calls;
  before(async () => {
    keyPair = await generateKeyPair(true);
    raw = await exportPublicKeyRaw(keyPair.publicKey);
    server = createWshServer({ auth: { authorizedKeys: await exportPublicKeySSH(keyPair.publicKey) }, exec: true });
    const { port } = await server.listen();
    url = `ws://127.0.0.1:${port}`;
  });
  after(() => server.close());

  // A signer that holds the private key privately (as a page / wallet / hardware token would).
  const makeSigner = (publicKey = raw) => {
    calls = [];
    return { publicKey, sign: async (data) => { calls.push(data); return sign(keyPair.privateKey, data); } };
  };

  it('connect() authenticates with a signer holding a raw public key', async () => {
    const client = new WshClient();
    try {
      await client.connect(url, { username: 'alice', signer: makeSigner() });
      assert.equal(calls.length, 1);
      assert.ok(calls[0] instanceof Uint8Array);
    } finally { await client.disconnect(); }
  });

  it('accepts a CryptoKey public key too', async () => {
    const client = new WshClient();
    try {
      await client.connect(url, { username: 'alice', signer: makeSigner(keyPair.publicKey) });
      assert.equal(calls.length, 1);
    } finally { await client.disconnect(); }
  });

  it('accepts a synchronous sign()', async () => {
    const other = await generateKeyPair(true);
    void other;
    const client = new WshClient();
    try {
      const signer = { publicKey: raw, sign: (d) => { calls = [d]; return crypto.subtle.sign('Ed25519', keyPair.privateKey, d).then((s) => new Uint8Array(s)); } };
      await client.connect(url, { username: 'alice', signer });
    } finally { await client.disconnect(); }
  });

  it('static exec() works with a signer', async () => {
    const { stdout, exitCode } = await WshClient.exec(url, 'echo signed', { username: 'alice', signer: makeSigner(), timeout: 5000 });
    assert.equal(dec.decode(stdout), 'signed\n');
    assert.equal(exitCode, 0);
  });

  it('a signer for a key that is not authorized is refused', async () => {
    const stranger = await generateKeyPair(true);
    const signer = { publicKey: await exportPublicKeyRaw(stranger.publicKey), sign: (d) => sign(stranger.privateKey, d) };
    const client = new WshClient();
    await assert.rejects(client.connect(url, { username: 'alice', signer }), /Authentication failed/);
  });

  it('a wrong signature (signer lies about its key) is refused', async () => {
    const stranger = await generateKeyPair(true);
    const signer = { publicKey: raw, sign: (d) => sign(stranger.privateKey, d) };
    const client = new WshClient();
    await assert.rejects(client.connect(url, { username: 'alice', signer }), /Authentication failed/);
  });

  it('rejects a malformed signer and keyPair + signer together', async () => {
    await assert.rejects(new WshClient().connect(url, { username: 'alice', signer: { publicKey: raw } }), /signer/);
    await assert.rejects(new WshClient().connect(url, { username: 'alice', signer: { publicKey: new Uint8Array(5), sign() {} } }), /signer/);
    await assert.rejects(new WshClient().connect(url, { username: 'alice', keyPair, signer: makeSigner() }), /keyPair.*signer|signer.*keyPair/);
  });

  it('a signer whose sign() returns the wrong length is reported, not sent', async () => {
    const signer = { publicKey: raw, sign: async () => new Uint8Array(3) };
    await assert.rejects(new WshClient().connect(url, { username: 'alice', signer }), /64-byte|signature/);
  });

  it('the keyPair path still works', async () => {
    const client = new WshClient();
    try {
      await client.connect(url, { username: 'alice', keyPair });
    } finally { await client.disconnect(); }
    await assert.rejects(new WshClient().connect(url, { username: 'alice' }), /keyPair/);
  });
});
