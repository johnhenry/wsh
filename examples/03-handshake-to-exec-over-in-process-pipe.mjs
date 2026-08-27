/**
 * Handshake to exec over an in-process pipe.
 *
 * A complete wsh conversation — HELLO → SERVER_HELLO → CHALLENGE → AUTH →
 * AUTH_OK, then OPEN(exec) → OPEN_OK → SESSION_DATA → EXIT — run entirely
 * in-process. Both endpoints speak real wire bytes (length-prefixed CBOR
 * frames through a FrameDecoder), so this is the same byte stream a Rust
 * server would see; only the socket is replaced by two callbacks.
 *
 * The tiny server below enforces the spec's ordering: it refuses to open
 * channels for clients that have not authenticated.
 */

import assert from 'node:assert/strict';
import {
  frameEncode, FrameDecoder,
  MSG, msgName, CHANNEL_KIND, AUTH_METHOD,
  hello, serverHello, challenge, auth, authOk, authFail,
  open, openOk, openFail, sessionData, exit,
  generateKeyPair, generateNonce, signChallenge, exportPublicKeyRaw,
  importPublicKeyRaw, verifyChallenge, fingerprint,
} from '@johnhenry/wsh';

const transcript = [];
const log = (who, msg) => transcript.push(`${who} ${msgName(msg.type)}`);

// ── In-process "server" ───────────────────────────────────────────────

function makeServer(sendToClient, authorizedFingerprints) {
  const decoder = new FrameDecoder();
  const state = { sessionId: 'sess-' + Math.random().toString(36).slice(2, 8), nonce: null, authed: false };
  const send = (msg) => { log('  server →', msg); sendToClient(frameEncode(msg)); };

  return async (chunk) => {
    for (const msg of decoder.feed(chunk)) {
      log('client →', msg);
      switch (msg.type) {
        case MSG.HELLO: {
          state.nonce = generateNonce();
          send(serverHello({ sessionId: state.sessionId, features: ['exec'] }));
          send(challenge({ nonce: state.nonce, sessionId: state.sessionId }));
          break;
        }
        case MSG.AUTH: {
          const fp = await fingerprint(msg.public_key);
          const key = await importPublicKeyRaw(msg.public_key);
          const ok = authorizedFingerprints.has(fp) &&
            await verifyChallenge(key, msg.signature, state.sessionId, state.nonce);
          if (ok) {
            state.authed = true;
            send(authOk({ sessionId: state.sessionId, token: 'resume-token', ttl: 3600 }));
          } else {
            send(authFail({ reason: 'signature or key rejected' }));
          }
          break;
        }
        case MSG.OPEN: {
          if (!state.authed) { send(openFail({ reason: 'not authenticated' })); break; }
          assert.equal(msg.kind, CHANNEL_KIND.EXEC);
          send(openOk({ channelId: 1, dataMode: 'virtual' }));
          // "Run" the command and stream its output back.
          const output = `hello from ${msg.command}\n`;
          send(sessionData({ channelId: 1, data: new TextEncoder().encode(output) }));
          send(exit({ channelId: 1, code: 0 }));
          break;
        }
      }
    }
  };
}

// ── Wire the two endpoints together ───────────────────────────────────

const clientDecoder = new FrameDecoder();
const fromServer = [];
let serverIngest;
const clientSend = (msg) => serverIngest(frameEncode(msg));

// Client identity, pre-authorized on the server (authorized_keys style).
const { publicKey, privateKey } = await generateKeyPair();
const clientFp = await fingerprint(await exportPublicKeyRaw(publicKey));
serverIngest = makeServer(
  (bytes) => fromServer.push(...clientDecoder.feed(bytes)),
  new Set([clientFp]),
);

const nextFromServer = async (type) => {
  while (fromServer.length === 0) await new Promise((r) => setTimeout(r, 1));
  const msg = fromServer.shift();
  assert.equal(msg.type, type, `expected ${msgName(type)}, got ${msgName(msg.type)}`);
  return msg;
};

// ── The conversation ──────────────────────────────────────────────────

// 1. Opening a channel before authenticating is refused.
await clientSend(open({ kind: CHANNEL_KIND.EXEC, command: 'id' }));
await nextFromServer(MSG.OPEN_FAIL);
console.log('pre-auth OPEN refused, as the spec requires');

// 2. Handshake.
await clientSend(hello({ username: 'demo', authMethod: AUTH_METHOD.PUBKEY }));
const srvHello = await nextFromServer(MSG.SERVER_HELLO);
const chal = await nextFromServer(MSG.CHALLENGE);

// 3. Challenge-response auth (same crypto as example 02).
const { signature, publicKeyRaw } = await signChallenge(
  privateKey, publicKey, srvHello.session_id, chal.nonce
);
await clientSend(auth({ method: AUTH_METHOD.PUBKEY, signature, publicKey: publicKeyRaw }));
const ok = await nextFromServer(MSG.AUTH_OK);
console.log(`authenticated: session ${ok.session_id}, resume token "${ok.token}"`);

// 4. Exec a command over a channel.
await clientSend(open({ kind: CHANNEL_KIND.EXEC, command: 'uname', cols: 80, rows: 24 }));
await nextFromServer(MSG.OPEN_OK);
const data = await nextFromServer(MSG.SESSION_DATA);
const done = await nextFromServer(MSG.EXIT);

console.log(`exec output: ${JSON.stringify(new TextDecoder().decode(data.data))}`);
assert.equal(done.code, 0);

console.log('\nmessage flow:');
for (const line of transcript) console.log(`  ${line}`);
console.log('ok: full handshake and exec channel completed over wire-format frames');
