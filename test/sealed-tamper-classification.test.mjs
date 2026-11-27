// test/sealed-tamper-classification.test.mjs -- #292: what a relay can do to ONE sealed frame, byte by byte.
//
// A sealed session carries every message as an `EncryptedFrame` (type, channel_id, nonce, ciphertext, session_id; session_id is the
// LAST field on the wire). A receiver decides "this is a frame of my session" from the type, the channel and the session id; the
// ciphertext and nonce are then authenticated by AES-GCM and the strict counter. So changing the last byte of the wire message
// changes the session id, not the ciphertext: the message stopped being "a frame of this session" and used to be dropped as if it
// were a plain message the relay had injected, and the session stayed open.
//
// The questions that decide the severity, each pinned below:
//   (a) is a message so classified ever PROCESSED?                     no  -- 'a frame whose session id was altered is never processed'
//   (b) can a relay make an UNSEALED message accepted on a sealed one? no  -- 'a plain message injected on a sealed session is never processed' (+ the byte sweep)
//   (c) is the loss visible?  the next frame fails the counter and closes the session (never silent while traffic continues);
//       and a frame-shaped message that is not this session's now closes at once, as a frame that does not open does.
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { open, shutdown, error as errorMsg, WshClient, WebSocketTransport, generateKeyPair, exportPublicKeyRaw, MSG, cborEncode } from '@johnhenry/wsh';
import { createMemoryHost } from '@johnhenry/wsh/memory';
import { pipeUrl, newRendezvousId } from '@johnhenry/wsh/pipe-relay';
import { createInProcessPipeRelay } from '@johnhenry/wsh/testing';
import { WebSocketServer } from 'ws';
import { hostileRelay } from './helpers/hostile-relay.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (cond, what, ms = 5000) => {
  const t0 = Date.now();
  for (;;) { if (await cond()) return; if (Date.now() - t0 > ms) throw new Error(`timed out waiting for ${what}`); await sleep(10); }
};
const keyPair = await generateKeyPair(true);
const raw = await exportPublicKeyRaw(keyPair.publicKey);
const hostPair = await generateKeyPair(true);

const closers = [];
afterEach(async () => { for (const c of closers.splice(0).reverse()) await c().catch(() => {}); });

/** A sealed session through an in-process relay whose `tap` is `ctl.tap`. */
async function meet() {
  const ctl = { tap: null };
  const relay = await createInProcessPipeRelay({ tap: (info) => ctl.tap?.(info) });
  const ran = []; const logs = []; const refused = [];
  const host = createMemoryHost({
    auth: { authorizedKeys: [raw] }, hostKey: hostPair, dataStreams: false, sealSession: 'require',
    onLog: (l) => logs.push(l), onRefused: (r) => refused.push(r.reason),
    exec: async (command, io) => { ran.push(command); await io.write(`out:${command}\n`); return 0; },
  });
  const id = newRendezvousId();
  void host.accept(new relay.WebSocket(pipeUrl('ws://relay.test', id, 'host')), { remote: { address: 'pipe' } });
  const client = new WshClient({ transportFactories: {
    ws: () => new WebSocketTransport({ WebSocket: relay.WebSocket }), wt: () => { throw new Error('no webtransport'); },
  } });
  const state = { closed: false, errors: [] };
  client.onClose = () => { state.closed = true; };
  client.onError = (e) => state.errors.push(e);
  closers.push(async () => { await client.disconnect().catch(() => {}); await host.close(); await relay.close(); });
  await client.connect(pipeUrl('ws://relay.test', id), { transport: 'ws', username: 'alice', keyPair, sealSession: true });
  assert.equal(client.sessionSealed, true);
  return { ctl, relay, host, client, ran, logs, refused, state };
}

/** A sealed session through the message-level hostile relay (test/helpers/hostile-relay.mjs): it can drop, change and write plain messages. */
async function through(hooks = {}) {
  const ran = []; const logs = [];
  const host = createMemoryHost({
    auth: { authorizedKeys: [raw] }, hostKey: hostPair, dataStreams: false, sealSession: 'require', onLog: (l) => logs.push(l),
    exec: async (command, io) => { ran.push(command); await io.write(`out:${command}\n`); return 0; },
  });
  const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise((r) => wss.once('listening', r));
  wss.on('connection', (ws) => { void host.accept(ws); });
  const relay = await hostileRelay(`ws://127.0.0.1:${wss.address().port}`, hooks);
  const client = new WshClient();
  const state = { closed: false };
  client.onClose = () => { state.closed = true; };
  closers.push(async () => { await client.disconnect().catch(() => {}); await relay.close(); for (const c of wss.clients) c.terminate(); wss.close(); await host.close(); });
  await client.connect(relay.url, { username: 'alice', keyPair, transport: 'ws', sealSession: true });
  return { ran, logs, relay, client, state };
}


/** Change the next message of `dir` that is a sealed frame (the wire bytes decode to ENCRYPTED_FRAME), once. */
const tamperNextFrame = (ctl, dir, change) => {
  let done = false;
  ctl.tap = ({ to, bytes }) => {
    if (done || to !== dir) return undefined;
    const bad = change(Uint8Array.from(bytes));
    done = true;
    return bad;
  };
};
const flipLast = (b) => { b[b.length - 1] ^= 1; return b; };

describe('a sealed frame whose LAST byte is changed (#292)', () => {
  it('the last byte of the wire message is the end of the session id', async () => {
    const s = await meet();
    let seen = null;
    s.ctl.tap = ({ to, bytes }) => { if (to === 'host' && !seen) seen = bytes; return undefined; };
    await s.client.openSession({ type: 'exec', command: 'probe' }).catch(() => {});
    await until(() => seen, 'a frame to cross');
    // The relay's message is a transport frame holding one length-prefixed CBOR message; the CBOR map ends with its last field.
    const id = s.client.sessionId;
    assert.equal(Buffer.from(seen).subarray(-id.length).toString(), id, 'the wire message ends with the session id text');
    assert.ok(Buffer.from(seen).includes(Buffer.from('session_id')), 'and it is a frame that names the session in a field');
  });

  it('toward the host: the session closes (fail closed), the host says why, and nothing runs', async () => {
    const s = await meet();
    tamperNextFrame(s.ctl, 'host', flipLast);
    const outcome = await s.client.openSession({ type: 'exec', command: 'must-not-run', timeout: 500 }).then(() => 'opened', (e) => e.message);
    await until(() => s.state.closed, `the session to close (open said ${outcome})`);
    assert.ok(s.refused.includes('seal-failed'), `refused: ${s.refused} logs: ${s.logs.slice(-3)}`);
    assert.deepEqual(s.ran, []);
  });

  it('toward the client: the client closes with an error naming the frame', async () => {
    const s = await meet();
    tamperNextFrame(s.ctl, 'operator', flipLast);
    const session = await s.client.openSession({ type: 'exec', command: 'x', timeout: 500 }).catch((e) => e.message);
    await until(() => s.state.closed, `the client to close (open said ${typeof session === 'string' ? session : 'opened'})`);
    assert.ok(s.state.errors.some((e) => /sealed frame did not open|not a frame of this session/.test(e.message)), s.state.errors.map((e) => e.message).join('|'));
    assert.equal(s.client.droppedMessages.plaintext, 0, 'it was not filed under "plaintext"');
  });

  it('(a) a frame whose session id was altered is never processed: no command ran, nothing was answered', async () => {
    const s = await meet();
    tamperNextFrame(s.ctl, 'host', flipLast);
    await s.client.openSession({ type: 'exec', command: 'must-not-run', timeout: 500 }).catch(() => {});
    await sleep(300);
    assert.deepEqual(s.ran, []);
  });

  it('(c) the loss is visible: a frame the relay drops outright leaves a gap, and the next frame closes the session', async () => {
    // No tamper at all: one frame never arrives. The strict counter refuses whatever comes next, so a message is never lost
    // silently while the session carries traffic (the very last message of a session is what a relay can always withhold).
    let n = 0;
    const s = await through({ toRelay: (m) => (m.type === MSG.ENCRYPTED_FRAME && n++ === 0 ? null : m) });
    await s.client.openSession({ type: 'exec', command: 'lost', timeout: 1000 }).catch(() => {});
    await s.client.openSession({ type: 'exec', command: 'after-the-gap', timeout: 1000 }).catch(() => {});
    await until(() => s.state.closed, 'the session to close on the gap');
    assert.ok(s.logs.some((l) => /replay\/reorder detected/.test(l)), s.logs.slice(-3).join('|'));
    assert.deepEqual(s.ran, [], 'neither the lost command nor the one after the gap ran');
  });
});

/** A bit the transport never read (a reserved flag) changes nothing, so the command may run: what must never happen is a command that was not sent, or run twice. */
const assertOnlySent = (ran, where) => {
  for (const c of ran) assert.ok(['sweep-command', 'after'].includes(c), `${where}: ran ${JSON.stringify(c)}, which nobody sent`);
  assert.equal(new Set(ran).size, ran.length, `${where}: a command ran twice`);
};

describe('(b) a message that is not sealed is never accepted on a sealed session (#292)', () => {
  it('a plain Open (a command) injected toward the host is not run, and the session carries on', async () => {
    const s = await through();
    s.relay.context().injectToRelay(open({ kind: 'exec', command: 'injected-by-relay' }));
    await sleep(200);
    await s.client.openSession({ type: 'exec', command: 'real' });
    await sleep(200);
    assert.deepEqual(s.ran, ['real'], 'only the sealed command ran');
    assert.ok(s.logs.some((l) => /dropped a plaintext message/.test(l)), 'the host named what it dropped');
    assert.equal(s.state.closed, false, 'a plain message is dropped and the session carries on (as before)');
  });

  it('a plain Shutdown and Error injected toward the client are not heard', async () => {
    const s = await through();
    s.relay.context().injectToClient(shutdown({ reason: 'injected' }));
    s.relay.context().injectToClient(errorMsg({ code: 9, message: 'injected' }));
    await until(() => s.client.droppedMessages.plaintext === 2, 'both to be counted');
    assert.equal(s.state.closed, false);
    await s.client.openSession({ type: 'exec', command: 'real' });
    assert.deepEqual(s.ran, ['real']);
  });

  it('a single flipped bit anywhere in a sealed frame never runs the command or a changed one: the session closes or the frame is dropped', async () => {
    // Offsets: the start (type), the middle (nonce/ciphertext), and the whole tail (the session id). Each is a fresh session.
    let length = 0;
    {
      const s = await meet();
      let armed = true;
      s.ctl.tap = ({ to, bytes }) => { if (to === 'host' && armed) { armed = false; length = bytes.length; } return undefined; };
      await s.client.openSession({ type: 'exec', command: 'sweep-command' });
      assert.ok(length > 80, `frame length ${length}`);
    }
    const offsets = [0, 1, 2, 3, 4, 5, 10, 20, length >> 1, length - 40, length - 37, length - 36, length - 10, length - 2, length - 1];
    for (const at of offsets) {
      const s = await meet();
      tamperNextFrame(s.ctl, 'host', (b) => { b[at] ^= 1; return b; });
      await s.client.openSession({ type: 'exec', command: 'sweep-command', timeout: 400 }).catch(() => {});
      await sleep(150);
      assertOnlySent(s.ran, `offset ${at}/${length}`);
      // A frame that was dropped leaves a gap: whatever is sent next is refused, and nothing it carries runs either.
      await s.client.openSession({ type: 'exec', command: 'after', timeout: 400 }).catch(() => {});
      await sleep(150);
      assertOnlySent(s.ran, `offset ${at}/${length} (after)`);
    }
  });
});
