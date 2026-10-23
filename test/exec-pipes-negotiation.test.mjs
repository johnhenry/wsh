// test/exec-pipes-negotiation.test.mjs -- exec stdin EOF against a virtual-mode host (#105).
//
// The Rust wsh-server carries stdin as SessionData control messages (data_mode
// virtual). Newer ones advertise `exec-pipes`: `Open.stdio = "pipes"` runs exec
// on plain pipes, stderr arrives on OpenOk.stderr_channel_id, and a zero-length
// SessionData is the stdin EOF. This file pins the negotiation with a mock host
// in both generations:
//   - new client + old host: clear error, no hang, nothing the old host would
//     reject (its Open decoding is deny_unknown_fields) is ever sent;
//   - old client (no `stdio`) + new host: exactly the historical PTY-style open.
// The real binary is covered by test/rust/wsh-rust-server.test.mjs.

import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { WebSocketServer } from 'ws';
import { WshClient } from '../src/client.mjs';
import { QMuxConnection } from '../src/qmux-connection.mjs';
import { FrameDecoder, frameEncode } from '../src/cbor.mjs';
import {
  MSG, serverHello, challenge, authOk, openOk, openFail, exit as exitMsg, close as closeMsg, sessionData,
} from '../src/messages.gen.mjs';
import { generateKeyPair } from '../src/auth.mjs';

const enc = new TextEncoder();
const dec = new TextDecoder();
const CH = 7;
const ERR_CH = 8;

/**
 * A virtual-mode host. `pipes: true` is the new Rust server (advertises
 * exec-pipes, grants stdio "pipes"); `pipes: false` is an old one, which fails
 * loudly on an Open carrying a field it does not know and otherwise behaves as a
 * PTY: input is echoed back and there is no EOF.
 */
async function virtualHost({ pipes }) {
  const wss = new WebSocketServer({ port: 0, host: '127.0.0.1' });
  await new Promise((r) => wss.once('listening', r));
  const log = { opens: [], inbound: [], eofs: 0 };
  wss.on('connection', (ws) => {
    const qmux = new QMuxConnection({ isClient: false, send: (b) => ws.send(b) });
    const decoder = new FrameDecoder();
    let control = null;
    let granted = false;
    let received = [];
    const send = (m) => control.write(frameEncode(m));

    qmux.onStreamOpen = (s) => {
      if (s.id !== 0) return;
      control = s;
      s.onData = (d) => { for (const m of decoder.feed(d)) onMessage(m); };
    };

    async function onMessage(m) {
      if (m.type === MSG.HELLO) {
        await send(serverHello({ sessionId: 's1', features: pipes ? ['exec-pipes'] : [] }));
        await send(challenge({ nonce: new Uint8Array(32).fill(1), sessionId: 's1' }));
      } else if (m.type === MSG.AUTH) {
        await send(authOk({ sessionId: 's1', token: new Uint8Array(16), ttl: 60 }));
      } else if (m.type === MSG.OPEN) {
        log.opens.push(m);
        if (!pipes && 'stdio' in m) {
          await send(openFail({ reason: 'unknown field `stdio`' }));
          return;
        }
        granted = pipes && m.stdio === 'pipes';
        await send(openOk({
          channelId: CH, dataMode: 'virtual', sessionId: 'x', token: new Uint8Array(4),
          capabilities: granted ? ['stdin-eof'] : [],
          stderrChannelId: granted ? ERR_CH : undefined,
        }));
      } else if (m.type === MSG.SESSION_DATA && m.channel_id === CH) {
        const n = m.data.byteLength;
        log.inbound.push(n);
        if (!granted) {
          // PTY-like: echo, never finish.
          await send(sessionData({ channelId: CH, data: m.data }));
        } else if (n > 0) {
          received.push(m.data);
        } else {
          log.eofs += 1;
          const all = Buffer.concat(received.map((b) => Buffer.from(b)));
          await send(sessionData({ channelId: ERR_CH, data: enc.encode('warn\n') }));
          await send(sessionData({ channelId: CH, data: all }));
          await send(exitMsg({ channelId: CH, code: 0 }));
          await send(closeMsg({ channelId: CH }));
        }
      }
    }
    qmux.sendHandshake();
    ws.on('message', (d) => qmux.receiveBytes(new Uint8Array(d)));
  });
  return {
    url: `ws://127.0.0.1:${wss.address().port}`,
    log,
    close: () => new Promise((r) => { for (const c of wss.clients) c.terminate(); wss.close(r); }),
  };
}

describe('exec stdin EOF negotiation (#105)', () => {
  let keyPair;
  before(async () => { keyPair = await generateKeyPair(true); });
  const run = (host, cmd, opts = {}) =>
    WshClient.exec(host.url, cmd, { username: 'u', keyPair, timeout: 5000, ...opts });

  it('new client + new host: stdin is piped, stderr is separate, EOF ends the command', async () => {
    const host = await virtualHost({ pipes: true });
    try {
      const { stdout, stderr, exitCode } = await run(host, 'cat', { stdin: 'a\nb\n' });
      assert.equal(dec.decode(stdout), 'a\nb\n');
      assert.equal(dec.decode(stderr), 'warn\n');
      assert.equal(exitCode, 0);
      assert.equal(host.log.opens[0].stdio, 'pipes');
      assert.equal(host.log.eofs, 1);
    } finally { await host.close(); }
  });

  it('empty stdin still sends the EOF', async () => {
    const host = await virtualHost({ pipes: true });
    try {
      const { stdout, exitCode } = await run(host, 'cat', { stdin: '' });
      assert.equal(stdout.byteLength, 0);
      assert.equal(exitCode, 0);
      assert.equal(host.log.eofs, 1);
    } finally { await host.close(); }
  });

  it('new client + new host: exec without stdin does not ask for pipes (unchanged)', async () => {
    const host = await virtualHost({ pipes: true });
    const client = new WshClient();
    try {
      await client.connect(host.url, { username: 'u', keyPair });
      assert.ok(client.hasFeature('exec-pipes'));
      const session = await client.openSession({ type: 'exec', command: 'echo hi' });
      assert.equal('stdio' in host.log.opens[0], false);
      assert.deepEqual(session.capabilities, []);
      assert.equal(session.stderrChannelId, undefined);
    } finally { await client.disconnect().catch(() => {}); await host.close(); }
  });

  it('old client + new host: a plain exec open is exactly the historical one, and closeStdin() still errors clearly', async () => {
    const host = await virtualHost({ pipes: true });
    const client = new WshClient();
    try {
      await client.connect(host.url, { username: 'u', keyPair });
      const session = await client.openSession({ type: 'exec', command: 'cat', primer: false });
      assert.deepEqual(Object.keys(host.log.opens[0]).sort(), ['cols', 'command', 'kind', 'rows', 'type']);
      await session.write('x');
      await assert.rejects(session.closeStdin(), /exec-pipes/);
      assert.equal(host.log.eofs, 0);
    } finally { await client.disconnect().catch(() => {}); await host.close(); }
  });

  it('new client + old host: exec({ stdin }) fails with a clear error instead of hanging, and sends nothing the old host rejects', async () => {
    const host = await virtualHost({ pipes: false });
    try {
      const started = Date.now();
      await assert.rejects(run(host, 'cat', { stdin: 'a\nb\n' }), /exec-pipes/);
      assert.ok(Date.now() - started < 4000, 'must fail fast, not time out');
      assert.equal(host.log.opens.length, 1);
      assert.equal('stdio' in host.log.opens[0], false);
    } finally { await host.close(); }
  });

  it('new client + old host: stdio "pipes" is refused before anything is sent', async () => {
    const host = await virtualHost({ pipes: false });
    try {
      await assert.rejects(run(host, 'cat', { stdio: 'pipes' }), /exec-pipes/);
      assert.equal(host.log.opens.length, 0);
    } finally { await host.close(); }
  });

  it('a zero-length write() on a pipes session is not mistaken for EOF', async () => {
    const host = await virtualHost({ pipes: true });
    const client = new WshClient();
    try {
      await client.connect(host.url, { username: 'u', keyPair });
      const session = await client.openSession({ type: 'exec', command: 'cat', stdio: 'pipes' });
      await session.write('');
      await session.write(new Uint8Array(0));
      await session.write('q');
      assert.equal(host.log.eofs, 0);
      await session.closeStdin();
      await session.closeStdin(); // idempotent
      await assert.rejects(session.write('late'), /stdin is closed/);
      await new Promise((r) => { session.onClose = r; });
      assert.equal(host.log.eofs, 1);
    } finally { await client.disconnect().catch(() => {}); await host.close(); }
  });

  it('openSession rejects a bad stdio value or a non-exec type', async () => {
    const host = await virtualHost({ pipes: true });
    const client = new WshClient();
    try {
      await client.connect(host.url, { username: 'u', keyPair });
      await assert.rejects(client.openSession({ type: 'exec', command: 'x', stdio: 'tty' }), TypeError);
      await assert.rejects(client.openSession({ type: 'pty', stdio: 'pipes' }), TypeError);
      assert.equal(host.log.opens.length, 0);
    } finally { await client.disconnect().catch(() => {}); await host.close(); }
  });
});
