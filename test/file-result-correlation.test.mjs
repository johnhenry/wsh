// wsh #72: concurrent file operations must each receive the FileResult for
// their own channel_id, not "the next FileResult of any channel".
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createWshServer } from '@johnhenry/wsh/server';
import { WshClient, WshTransport, MSG, generateKeyPair, exportPublicKeySSH } from '@johnhenry/wsh';

describe('FileResult correlation', () => {
  it('replies delivered out of request order still reach the right caller', async () => {
    const keyPair = await generateKeyPair(true);
    class Reversing extends WshTransport {
      ops = [];
      async _doConnect() {}
      async _doClose() {}
      async _doOpenStream() { throw new Error('unused'); }
      async _doSendControl(msg) {
        const reply = (m) => setTimeout(() => this._emitControl(m), 0);
        if (msg.type === MSG.HELLO) {
          reply({ type: MSG.SERVER_HELLO, session_id: 's', features: [] });
          reply({ type: MSG.CHALLENGE, nonce: new Uint8Array(32), session_id: 's' });
        } else if (msg.type === MSG.AUTH) {
          reply({ type: MSG.AUTH_OK, session_id: 's' });
        } else if (msg.type === MSG.FILE_OP) {
          this.ops.push(msg);
          if (this.ops.length === 2) {
            // answer the SECOND request first
            for (const op of [...this.ops].reverse()) {
              reply({ type: MSG.FILE_RESULT, channel_id: op.channel_id, success: true, metadata: { path: op.path }, entries: [] });
            }
          }
        }
      }
    }
    const client = new WshClient();
    await client.connectWithTransport(new Reversing(), 'wsh://x/', { username: 'alice', keyPair });
    const [a, b] = await Promise.all([client.fileStat('/a'), client.fileStat('/b')]);
    assert.equal(a.metadata.path, '/a');
    assert.equal(b.metadata.path, '/b');
  });

  describe('against the server', () => {
    let root; let ctx; let client;
    before(async () => {
      root = await mkdtemp(path.join(tmpdir(), 'wsh-corr-'));
      await writeFile(path.join(root, 'one.txt'), 'first file');
      await writeFile(path.join(root, 'two.txt'), 'second, longer file');
      const keyPair = await generateKeyPair(true);
      const server = createWshServer({ auth: { authorizedKeys: await exportPublicKeySSH(keyPair.publicKey) }, fs: { root } });
      const { port } = await server.listen();
      ctx = { server };
      client = new WshClient();
      await client.connect(`ws://127.0.0.1:${port}`, { username: 'alice', keyPair });
    });
    after(async () => { await client.disconnect(); await ctx.server.close(); await rm(root, { recursive: true, force: true }); });

    it('concurrent fileStat and fileRead each get their own result', async () => {
      const dec = new TextDecoder();
      const [s1, s2, r1, r2] = await Promise.all([
        client.fileStat('one.txt'), client.fileStat('two.txt'),
        client.fileRead('one.txt', 0, 100), client.fileRead('two.txt', 0, 100),
      ]);
      assert.equal(s1.metadata.name, 'one.txt');
      assert.equal(s2.metadata.name, 'two.txt');
      assert.equal(dec.decode(r1.metadata.data), 'first file');
      assert.equal(dec.decode(r2.metadata.data), 'second, longer file');
    });

    it('a slow multi-chunk fileWrite does not steal (or lose) a concurrent fileStat result', async () => {
      const big = new Uint8Array(300_000).fill(7);
      const [w, st] = await Promise.all([client.fileWrite('big.bin', big), client.fileStat('one.txt')]);
      assert.equal(w.metadata.written, 300_000);
      assert.equal(st.metadata.name, 'one.txt');
    });
  });
});
