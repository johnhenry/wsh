// test/seal-require-auth.test.mjs -- #240: with `sealSession: 'require'`, where does a client that never seals stand relative to the host's
// `auth` callback? The protocol sends the key exchange AFTER the login succeeded (the exchange is signed with the login key and its
// transcript is bound to the session the login created), so the host cannot know before `auth` that a client will not seal: `auth` runs
// once for it. What the host does guarantee is checked here, for every JS host: `auth` is told `sealRequired: true`, `onSealed` fires only
// for a client that did seal (that is where to count), and the client that does not seal is served nothing and refused at its first message.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { WebSocket as WsClient } from 'ws';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { createWshServer } from '@johnhenry/wsh/server';
import { createPipeRelay, newRendezvousId, pipeUrl } from '@johnhenry/wsh/pipe-relay';
import { WshClient, generateKeyPair } from '@johnhenry/wsh';

const until = async (cond, what, ms = 4000) => {
  const t0 = Date.now();
  for (;;) { const v = await cond(); if (v) return v; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await new Promise((r) => setTimeout(r, 10)); }
};
const echo = async (command, io) => { await io.write(`ran:${command}\n`); return 0; };

/** The hooks a host embedder counts with, and what ran. */
function probe() {
  const p = { authCalls: [], sealed: [], refused: [], ran: [] };
  p.auth = async (who) => { p.authCalls.push({ ...who }); return true; };
  p.onSealed = (who) => p.sealed.push({ ...who });
  p.onRefused = (r) => p.refused.push(r);
  p.exec = async (command, io) => { p.ran.push(command); return echo(command, io); };
  return p;
}

/** A way to stand up each host kind, connect a client to it with `sealSession`, and close it. */
const hosts = {
  'createMemoryHost': async (p) => {
    const host = createMemoryHost({ auth: p.auth, exec: p.exec, hostKey: true, dataStreams: false, sealSession: 'require', onSealed: p.onSealed, onRefused: p.onRefused });
    return { connect: (opts) => host.connect({ username: 'alice', ...opts }), close: () => host.close() };
  },
  'createWshServer (accept, no data streams)': async (p) => {
    const relay = createPipeRelay();
    const { port } = await relay.listen();
    const server = createWshServer({ auth: p.auth, exec: p.exec, hostKey: true, sealSession: 'require', onSealed: p.onSealed, onRefused: p.onRefused });
    const sockets = [];
    return {
      async connect({ keyPair, sealSession }) {
        const id = newRendezvousId();
        const ws = new WsClient(pipeUrl(`ws://127.0.0.1:${port}`, id, 'host'));
        sockets.push(ws);
        await new Promise((resolve, reject) => { ws.once('open', resolve); ws.once('error', reject); });
        await server.accept(ws, { dataStreams: false });
        const client = new WshClient();
        await client.connect(pipeUrl(`ws://127.0.0.1:${port}`, id), { username: 'alice', keyPair, sealSession, timeout: 4000, transport: 'ws' });
        return client;
      },
      async close() { for (const s of sockets) s.terminate(); await server.close(); await relay.close(); },
    };
  },
};

for (const [label, make] of Object.entries(hosts)) {
  describe(`sealSession: 'require' and the auth callback: ${label}`, () => {
    it('a client that seals: auth runs once, told sealRequired: true, then onSealed fires once, and it is served', async () => {
      const p = probe(); const host = await make(p); const keyPair = await generateKeyPair(true);
      try {
        const client = await host.connect({ keyPair, sealSession: true });
        const session = await client.openSession({ type: 'exec', command: 'hello' });
        const out = []; session.onData = (d) => out.push(Buffer.from(d));
        await until(() => Buffer.concat(out).toString().includes('ran:hello'), 'the output');
        assert.equal(p.authCalls.length, 1);
        assert.equal(p.authCalls[0].sealRequired, true, 'the callback is told the session is not yet one that can do anything');
        assert.equal(p.sealed.length, 1);
        assert.equal(p.sealed[0].username, 'alice');
        assert.deepEqual(p.ran, ['hello']);
        await client.disconnect();
      } finally { await host.close(); }
    });

    it('a client that does not seal: auth ran once (the protocol logs in first), onSealed never fires, nothing is served, and it is refused as not-sealed at its first message', async () => {
      const p = probe(); const host = await make(p); const keyPair = await generateKeyPair(true);
      try {
        const client = await host.connect({ keyPair, sealSession: false });
        assert.equal(p.authCalls.length, 1, 'documented: counting in `auth` counts this client; count in onSealed');
        assert.equal(p.authCalls[0].sealRequired, true, 'and the callback can tell, to skip the count');
        assert.equal(p.sealed.length, 0);
        await assert.rejects(client.openSession({ type: 'exec', command: 'must-not-run', timeout: 1500 }));
        await until(() => p.refused.length, 'the refusal');
        assert.equal(p.refused.length, 1, 'one refusal per connection');
        assert.equal(p.refused[0].reason, 'not-sealed');
        assert.deepEqual(p.ran, [], 'the command never ran');
        assert.equal(p.sealed.length, 0, 'and it never counts as sealed');
        await client.disconnect().catch(() => {});
      } finally { await host.close(); }
    });

  });
}
