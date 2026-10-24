// test/abort-signal.test.mjs -- AbortSignal for upload / download / callTool, McpCancel, getSession (#108).
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, readFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createWshServer } from '@johnhenry/wsh/server';
import { WshClient, WshMcpBridge, generateKeyPair, exportPublicKeySSH, MCP_CANCEL_FEATURE } from '@johnhenry/wsh';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (fn, ms = 3000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (await fn()) return true; await sleep(10); }
  return false;
};
const isAbort = (e) => e?.name === 'AbortError';

describe('AbortSignal on upload / download / callTool (#108)', () => {
  let keyPair, server, url, root, client;
  const logs = [];
  const events = [];

  before(async () => {
    keyPair = await generateKeyPair(true);
    const authorizedKeys = `${await exportPublicKeySSH(keyPair.publicKey)} alice@test\n`;
    root = await mkdtemp(join(tmpdir(), 'wsh-abort-'));
    server = createWshServer({
      auth: { authorizedKeys },
      exec: true,
      fs: { root, maxFileBytes: 64 * 1024 * 1024 },
      onLog: (l) => logs.push(l),
      mcp: {
        timeoutMs: 5000,
        tools: [
          { name: 'echo', description: 'echo', call: (a) => a },
          { name: 'hang', description: 'waits for its signal',
            call: (args, { signal }) => new Promise((resolve, reject) => {
              events.push('hang-started');
              signal.addEventListener('abort', () => { events.push('hang-aborted'); reject(new Error('stopped')); }, { once: true });
            }) },
        ],
      },
    });
    const { port } = await server.listen();
    url = `ws://127.0.0.1:${port}`;
    client = new WshClient();
    await client.connect(url, { username: 'alice', keyPair });
  });
  after(async () => { await client.disconnect(); await server.close(); await rm(root, { recursive: true, force: true }); });

  const big = (n) => new Uint8Array(n).map((_, i) => i & 255);

  describe('upload', () => {
    it('already-aborted signal starts nothing', async () => {
      const before = client.listSessions().length;
      const mark = logs.length;
      const ac = new AbortController(); ac.abort();
      await assert.rejects(client.upload(big(10), 'pre.bin', { signal: ac.signal }), isAbort);
      assert.equal(client.listSessions().length, before);
      assert.equal(logs.slice(mark).filter((l) => /upload/.test(l)).length, 0);
      assert.deepEqual((await readdir(root)).filter((f) => f === 'pre.bin'), []);
    });

    it('abort mid-upload rejects with AbortError, closes the channel, and leaves no file', async () => {
      const ac = new AbortController();
      const mark = logs.length;
      const p = client.upload(big(8 * 1024 * 1024), 'partial.bin', {
        signal: ac.signal,
        onProgress: (sent) => { if (sent >= 128 * 1024) ac.abort(); },
      });
      await assert.rejects(p, isAbort);
      assert.ok(await until(() => logs.slice(mark).some((l) => /upload .*partial\.bin.*closed before completion/.test(l))), 'server saw the channel close');
      await sleep(50);
      assert.deepEqual((await readdir(root)).filter((f) => f.includes('partial')), [], 'nothing is left behind');
      assert.ok(client.listSessions().every((s) => s.state === 'closed' || s.kind !== 'file'));
    });

    it('abort mid-upload does not clobber an existing file', async () => {
      await writeFile(join(root, 'keep.bin'), 'original');
      const ac = new AbortController();
      await assert.rejects(client.upload(big(8 * 1024 * 1024), 'keep.bin', {
        signal: ac.signal, onProgress: (s) => { if (s >= 64 * 1024) ac.abort(); },
      }), isAbort);
      await sleep(100);
      assert.equal(await readFile(join(root, 'keep.bin'), 'utf8'), 'original');
    });

    it('a signal that never fires changes nothing', async () => {
      const ac = new AbortController();
      await client.upload(big(300_000), 'ok.bin', { signal: ac.signal });
      assert.equal((await readFile(join(root, 'ok.bin'))).byteLength, 300_000);
      ac.abort(); // after completion: harmless
    });
  });

  describe('download', () => {
    it('already-aborted signal starts nothing', async () => {
      await writeFile(join(root, 'd.bin'), big(1000));
      const before = client.listSessions().length;
      const ac = new AbortController(); ac.abort(new Error('nope'));
      await assert.rejects(client.download('d.bin', { signal: ac.signal }), isAbort);
      assert.equal(client.listSessions().length, before);
    });

    it('abort mid-download rejects with AbortError and the server sees the channel close', async () => {
      await writeFile(join(root, 'dl.bin'), big(16 * 1024 * 1024));
      const ac = new AbortController();
      const mark = logs.length;
      const p = client.download('dl.bin', { signal: ac.signal, onProgress: ({ received }) => { if (received >= 64 * 1024) ac.abort(); } });
      await assert.rejects(p, isAbort);
      assert.ok(await until(() => logs.slice(mark).some((l) => /download .*dl\.bin.*closed before completion/.test(l))), 'server saw the channel close');
    });

    it('works normally with a live signal', async () => {
      const ac = new AbortController();
      const data = await client.download('d.bin', { signal: ac.signal });
      assert.equal(data.byteLength, 1000);
    });
  });

  describe('callTool', () => {
    it('advertises mcp-cancel', () => {
      assert.ok(client.hasFeature(MCP_CANCEL_FEATURE));
    });

    it('already-aborted signal sends nothing', async () => {
      events.length = 0;
      const ac = new AbortController(); ac.abort();
      await assert.rejects(client.callTool('hang', {}, { signal: ac.signal }), isAbort);
      await sleep(50);
      assert.deepEqual(events, []);
    });

    it('abort mid-call rejects with AbortError and the server handler sees its signal fire', async () => {
      events.length = 0;
      const ac = new AbortController();
      const p = client.callTool('hang', {}, { signal: ac.signal, timeout: 10_000 });
      assert.ok(await until(() => events.includes('hang-started')));
      ac.abort();
      await assert.rejects(p, isAbort);
      assert.ok(await until(() => events.includes('hang-aborted')), 'server handler was told to stop');
    });

    it('the connection stays usable and the late reply does not leak into the next call', async () => {
      assert.deepEqual(await client.callTool('echo', { a: 1 }), { a: 1 });
    });

    it('a numeric third argument is still the timeout', async () => {
      await assert.rejects(client.callTool('hang', {}, 80), /Timed out/);
    });

    it('cancelling one call leaves a concurrent call alone', async () => {
      events.length = 0;
      const ac = new AbortController();
      const a = client.callTool('hang', {}, { signal: ac.signal });
      const b = client.callTool('echo', { k: 'v' });
      assert.deepEqual(await b, { k: 'v' });
      ac.abort();
      await assert.rejects(a, isAbort);
    });
  });

  describe('WshMcpBridge.call', () => {
    it('already-aborted signal sends nothing', async () => {
      events.length = 0;
      const ac = new AbortController(); ac.abort();
      await assert.rejects(new WshMcpBridge(client).call('hang', {}, { signal: ac.signal }), isAbort);
      await sleep(50);
      assert.ok(!events.includes('hang-started'));
    });

    it('abort mid-call rejects with AbortError and the server handler is told to stop', async () => {
      events.length = 0;
      const bridge = new WshMcpBridge(client);
      const ac = new AbortController();
      const p = bridge.call('hang', {}, { signal: ac.signal, timeout: 10_000 });
      assert.ok(await until(() => events.includes('hang-started')));
      ac.abort();
      await assert.rejects(p, isAbort);
      assert.ok(await until(() => events.includes('hang-aborted')));
      assert.equal((await bridge.call('echo', { success: true, output: 'x' })).output, 'x');
    });
  });

  describe('getSession', () => {
    it('writes to and closes a session by channel id and by session id', async () => {
      const opened = await client.openSession({ type: 'exec', command: 'cat' });
      const info = client.listSessions().find((s) => s.channelId === opened.channelId);
      assert.ok(info);
      const s = client.getSession(info.channelId);
      assert.equal(s, opened);
      assert.equal(client.getSession(opened.sessionId), opened);
      const chunks = [];
      s.onData = (d) => chunks.push(d);
      await s.write('ping\n');
      assert.ok(await until(() => Buffer.concat(chunks).toString().includes('ping')));
      await s.close();
      assert.equal(client.getSession(info.channelId)?.state ?? 'closed', 'closed');
    });

    it('returns undefined for an unknown id', () => {
      assert.equal(client.getSession(999999), undefined);
      assert.equal(client.getSession('nope'), undefined);
    });
  });
});

describe('McpCancel is gated on the mcp-cancel feature', () => {
  const mk = async (features) => {
    const { WshTransport } = await import('../src/transport.mjs');
    const { MSG, serverHello } = await import('../src/messages.gen.mjs');
    const { WshClient: C } = await import('../src/client.mjs');
    class T extends WshTransport {
      sent = [];
      async _doConnect() {}
      async _doClose() {}
      async _doOpenStream() { throw new Error('not used'); }
      async _doSendControl(msg) {
        this.sent.push(msg);
        if (msg.type === MSG.HELLO) {
          setTimeout(() => this._emitControl(serverHello({ sessionId: 's', features, fingerprints: [] })), 0);
          setTimeout(() => this._emitControl({ type: MSG.CHALLENGE, nonce: new Uint8Array(32).fill(7), session_id: 's' }), 0);
        } else if (msg.type === MSG.AUTH) setTimeout(() => this._emitControl({ type: MSG.AUTH_OK }), 0);
        // McpCall is never answered.
      }
    }
    const transport = new T();
    const client = new C({ transportFactories: { ws: () => transport } });
    await client.connect('ws://test.invalid', { username: 'alice', keyPair: await generateKeyPair(true), transport: 'ws' });
    return { client, transport, MSG };
  };

  it('a server without mcp-cancel: abort rejects locally and no McpCancel is sent', async () => {
    const { client, transport, MSG } = await mk(['mcp', 'mcp-call-id']);
    const ac = new AbortController();
    const p = client.callTool('t', {}, { signal: ac.signal });
    await sleep(20);
    ac.abort();
    await assert.rejects(p, isAbort);
    await sleep(20);
    assert.equal(transport.sent.filter((m) => m.type === MSG.MCP_CANCEL).length, 0);
  });

  it('a server with mcp-cancel: abort sends McpCancel carrying the call_id', async () => {
    const { client, transport, MSG } = await mk(['mcp', 'mcp-call-id', 'mcp-cancel']);
    const ac = new AbortController();
    const p = client.callTool('t', {}, { signal: ac.signal });
    await sleep(20);
    ac.abort();
    await assert.rejects(p, isAbort);
    await sleep(20);
    const call = transport.sent.find((m) => m.type === MSG.MCP_CALL);
    const cancels = transport.sent.filter((m) => m.type === MSG.MCP_CANCEL);
    assert.equal(cancels.length, 1);
    assert.equal(cancels[0].call_id, call.call_id);
  });

  it('a server without mcp-call-id: abort rejects the caller but the queue slot is held until the stale reply or timeout', async () => {
    const { client } = await mk(['mcp']);
    const ac = new AbortController();
    const p = client.callTool('t', {}, { signal: ac.signal });
    await sleep(20);
    ac.abort();
    await assert.rejects(p, isAbort);
  });
});
