// test/rust/wsh-rust-server.test.mjs — real client-server round trips against
// the ACTUAL Rust `wsh-server` binary (crates/wsh-server), driven by this
// repo's own JS client (src/index.mjs, not mocks).
//
// Moved here from erisera-code/clawser's tools/test/wsh-rust-server.test.mjs
// on 2026-09-06 when the Rust workspace itself moved into this repo (#52).
// It originally mirrored the pattern used by clawser's
// tools/test/wsh-server.test.mjs for clawser's Node reimplementation of the
// server (tools/wsh-server.mjs) — that Node-server suite, and the Node
// server itself, stayed behind in clawser; only the tests that exercise the
// real Rust binary moved. Historical comments below referencing clawser
// paths (crates/..., docs/WSH-INTO-CLAWSER.md) describe fixes made before
// the move and are kept for record.
//
// Prerequisite: the Rust binary must already be built before running this file:
//   cargo build --release -p wsh-server
// (this suite spawns target/release/wsh-server, or $WSH_SERVER_BIN if set,
// as a real subprocess). If the binary is missing, `before()` will build it
// automatically (debug build is NOT used here — release, to keep
// PTY/session-teardown timing realistic and the suite fast across many
// subprocess spawns).
//
// Kept out of the default `npm test` glob (test/*.test.mjs) since it needs a
// Rust toolchain and spawns real subprocesses. Run with:
//   npm run test:rust
// or directly:
//   node --test test/rust/wsh-rust-server.test.mjs
//
// ── Why this file exists ────────────────────────────────────────────
//
// wsh-server (Rust) was restored from git history months after the JS client
// (@johnhenry/wsh) had been written/tested against an *assumed*-compatible
// wire protocol (mostly validated against the Node reimplementation in
// tools/wsh-server.mjs). This suite is the actual cross-implementation check:
// does the real Rust server speak the same WebSocket framing, CBOR envelope
// shape, and auth handshake the JS client expects?
//
// It found and required fixing one real, non-cosmetic protocol gap: the Rust
// server was declaring `data_mode: "stream"` for exec/pty channels opened
// over WebSocket, which tells @johnhenry/wsh's WshClient to open a second
// multiplexed data stream (a FRAME_OPEN_STREAM 0x03 frame) for session I/O.
// But neither the Rust server's WebSocket transport (crates/wsh-server/src/
// transport/websocket.rs — `ws_recv_control` only ever accepts FRAME_CONTROL
// 0x01 frames and hard-errors on anything else) nor its WebTransport
// transport (crates/wsh-server/src/server.rs `handle_webtransport` only ever
// accepts a single bidirectional stream, used for control) ever implemented
// a second data stream. There was also no PTY-output-to-client pump at all
// in crates/wsh-server/src/server.rs — direct-host WS sessions never
// delivered PTY output before this. Fixed on the Rust side (this repo's
// crates/wsh-server/src/server.rs + crates/wsh-server/src/session/pty.rs) by:
//   1. Setting `data_mode: SessionDataMode::Virtual` for newly opened
//      exec/pty channels (both WS and WebTransport share this code path via
//      `dispatch_message`), which tells the JS client to send/receive session
//      I/O as SessionData control-channel envelopes instead of opening a
//      stream.
//   2. Adding `WshServer::spawn_pty_output_pump`, a background task that
//      reads PTY output (via `PtyHandle::reader()`, already present but
//      previously unused/dead code) and forwards it to the client as
//      SessionData envelopes through the existing `ctx.peer_tx` channel
//      (already drained by both `session_loop_ws` and `session_loop_quic`
//      for other message types, e.g. relay-forwarded traffic), then sends
//      Exit + Close once the child process terminates
//      (`PtyHandle::child_handle()`, newly added, mirrors the existing
//      `reader()`/`writer()` accessors).
//   3. Adding a `(MsgType::SessionData, Payload::SessionData(p))` arm to
//      `dispatch_message` that writes client stdin straight to the PTY via
//      the existing `PtyHandle::write_blocking`.
// No changes were made to @johnhenry/wsh (node_modules) — it is treated as the
// fixed, currently-shipping standard this suite verifies the Rust server
// against.
//
// Update (wsh #22 PR 3 of 3): the live-caller decision recorded on wsh #22
// is to switch `exec` channels to `data_mode: 'stream'` in *both* of
// clawser's wsh servers (tools/wsh-server.mjs and this Rust server). This
// suite is exactly what caught why that flip isn't safe here yet: trying it
// reintroduced a close cousin of the original bug above. Declaring `Stream`
// without a real second multiplexed stream behind it doesn't just mean
// output silently doesn't arrive (survivable, since @johnhenry/wsh's
// WshSession still delivers SessionData to onData regardless of the
// session's declared data_mode) — `WshSession.close()` for a stream-mode
// session also *awaits its background read pump finishing*, which requires
// the server to eventually send data or a FIN on that stream. Since this
// server never touches it, every test below that closes a still-running
// `exec` session (session management / Attach-Resume: `session.close()` on
// a `sleep 5` session, not a naturally-exited one) hung forever. `exec`
// stays `data_mode: 'virtual'` here for now — see the long comment at the
// `data_mode` assignment in crates/wsh-server/src/server.rs's Open handler
// for the full accounting and what real follow-up work would unblock it.
// The actual live caller for wsh #22 PR 3 is tools/wsh-server.mjs, which
// does implement a real per-transport data stream (see its
// `#bindDataStream`) and switches `exec` to `data_mode: 'stream'` safely.
//
// ── WebTransport (QUIC) coverage ─────────────────────────────────────
//
// @johnhenry/wsh's `WebTransportTransport` calls the bare global
// `new WebTransport(url)`, which doesn't exist in plain Node — but
// `@fails-components/webtransport` (already a dependency of
// tools/wsh-server.mjs) ships a real Node *client* too, so assigning it to
// `globalThis.WebTransport` (subclassed only to inject
// `serverCertificateHashes` for pinning the server's self-signed dev cert —
// the real client calls the constructor with no options) lets
// @johnhenry/wsh's own transport code run completely unmodified over a real
// QUIC connection to this Rust server. Full end-to-end WebTransport
// interop — auth handshake through a real exec session — is verified this
// way below.
//
// Getting here took two real, non-obvious fixes on the Rust side, both
// found by a careful, from-scratch investigation (see
// docs/WSH-INTO-CLAWSER.md for the full account, including a false-positive
// detour that initially looked like the interop gap was unfixable):
//
//   1. The WebTransport spec's certificate-hash-pinning algorithm
//      (`serverCertificateHashes`) requires the pinned certificate's
//      validity period to be **at most 14 days** — confirmed independently
//      via the W3C spec and Firefox's own bugzilla history for this exact
//      feature (bugzilla.mozilla.org/1873263). rcgen's default validity
//      window (1975-01-01..4096-01-01) obviously fails this; so does any
//      "just make it not absurd" window longer than 14 days (365 days was
//      tried and confirmed to still fail). `generate_self_signed_cert()` in
//      crates/wsh-server/src/main.rs now uses a 13-day window with a day of
//      `not_before` slack for clock skew.
//   2. `handle_webtransport()` in crates/wsh-server/src/server.rs was
//      sending SERVER_HELLO then CHALLENGE back-to-back on one QUIC stream.
//      Unlike discrete WebSocket frames, a QUIC stream has no
//      message-boundary framing at that layer, so both writes can arrive in
//      a single client-side `read()` — and @johnhenry/wsh's WshClient
//      dispatches both messages synchronously from that one read, but only
//      registers its *next* waiter (for CHALLENGE) in a microtask after the
//      first `await` (for SERVER_HELLO) resolves. The synchronously-
//      dispatched CHALLENGE has no waiter yet and is silently dropped,
//      hanging until timeout — the exact same race already found and fixed
//      on the Node reimplementation's WebSocket path in
//      tools/wsh-server.mjs. Fixed the same way: skip SERVER_HELLO, send
//      only CHALLENGE, and use the client's documented "pending" literal
//      session-id fallback for transcript verification.

import { describe, it, before, after, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  WshClient,
  generateKeyPair,
  exportPublicKeySSH,
  exportPublicKeyRaw,
  hello, auth, reverseRegister, reverseAccept,
  signChallenge, signPeerRecord,
  FrameDecoder, frameEncode, cborDecode,
  QMuxConnection, SerialQueue,
  MSG,
} from '../../src/index.mjs';
import { WebTransport as RealWebTransport, quicheLoaded } from '@fails-components/webtransport';
import WebSocket from 'ws';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');
// Honor WSH_SERVER_BIN (e.g. a pre-built binary from a different target
// dir, or one downloaded from a rust-v* release) so CI/local runs don't
// always have to build from source.
const SERVER_BIN = process.env.WSH_SERVER_BIN || path.join(REPO_ROOT, 'target', 'release', 'wsh-server');

const STARTUP_GRACE_MS = 1200;
const PORT_BASE = 19400; // arbitrary high range unlikely to collide

let nextPort = PORT_BASE;
function allocPort() {
  return nextPort++;
}

// Preserve/restore NODE_TLS_REJECT_UNAUTHORIZED — the Rust server always
// wraps its WebSocket listener in TLS (self-signed cert via --generate-cert),
// unlike the Node reference server which supports plain ws://. Node's global
// WebSocket (used internally by @johnhenry/wsh's WebSocketTransport) has no
// per-connection custom-CA option, so the standard escape hatch is used here,
// scoped to this test file only.
const ORIGINAL_TLS_REJECT = process.env.NODE_TLS_REJECT_UNAUTHORIZED;

before(() => {
  if (!existsSync(SERVER_BIN)) {
    if (process.env.WSH_SERVER_BIN) {
      // An explicit WSH_SERVER_BIN was given but doesn't exist -- that's a
      // caller error (wrong path), not something we should paper over by
      // building a different binary at the default location.
      throw new Error(`WSH_SERVER_BIN=${SERVER_BIN} does not exist`);
    }
    execFileSync('cargo', ['build', '--release', '-p', 'wsh-server'], {
      cwd: REPO_ROOT,
      stdio: 'inherit',
    });
  }
  assert.ok(existsSync(SERVER_BIN), `expected built binary at ${SERVER_BIN}`);
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
});

after(() => {
  if (ORIGINAL_TLS_REJECT === undefined) {
    delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  } else {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = ORIGINAL_TLS_REJECT;
  }
});

/** @typedef {{ proc: import('node:child_process').ChildProcess, url: string, homeDir: string, logs: string[] }} RunningServer */

/**
 * Start a real `wsh-server` subprocess with a scratch $HOME (so
 * ~/.wsh/authorized_keys and the --generate-cert self-signed cert are
 * isolated per test), pre-populated with the given SSH-format public keys.
 *
 * The binary has no --authorized-keys / --port-scoped config flag for keys:
 * per crates/wsh-server/src/server.rs (`WshServer::new`) it unconditionally
 * loads `$HOME/.wsh/authorized_keys` (falling back to `$HOME/.ssh/authorized_keys`)
 * at startup via `dirs::home_dir()`, so isolation is done via a per-test
 * `$HOME` override rather than a CLI flag (there isn't one — see
 * crates/wsh-server/src/main.rs's `Cli` struct, which has no such option).
 *
 * @param {string[]} sshLines - authorized_keys lines (ssh-ed25519 ...)
 * @param {string[]} [extraArgs] - additional CLI flags, e.g. ['--enable-relay']
 * @returns {Promise<RunningServer>}
 */
async function startServer(sshLines, extraArgs = []) {
  const homeDir = mkdtempSync(path.join(tmpdir(), 'wsh-rust-server-test-'));
  const wshDir = path.join(homeDir, '.wsh');
  execFileSync('mkdir', ['-p', wshDir]);
  writeFileSync(path.join(wshDir, 'authorized_keys'), sshLines.join('\n') + '\n');

  const port = allocPort();
  const logs = [];
  const proc = spawn(
    SERVER_BIN,
    ['--port', String(port), '--generate-cert', '--config', '/dev/null/does-not-exist', ...extraArgs],
    {
      env: { ...process.env, HOME: homeDir },
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );
  proc.stdout.on('data', (d) => logs.push(d.toString()));
  proc.stderr.on('data', (d) => logs.push(d.toString()));

  // Wait for the actual "WebSocket TLS listener started" log line rather than
  // a fixed timer: cert generation (rcgen) + TLS listener bind time varies
  // with machine load, and a fixed STARTUP_GRACE_MS was observed to
  // occasionally race the real readiness signal (intermittent "WebSocket
  // connection failed" in the very first test of a run, ~1-in-6 under load).
  // STARTUP_GRACE_MS is kept as an upper-bound safety net only.
  await new Promise((resolve, reject) => {
    const deadline = setTimeout(() => {
      cleanup();
      reject(new Error(
        `wsh-server did not log readiness within ${STARTUP_GRACE_MS}ms: ${logs.join('')}`,
      ));
    }, STARTUP_GRACE_MS);

    function checkReady() {
      if (logs.some((l) => l.includes('WebSocket TLS listener started'))) {
        cleanup();
        resolve();
      }
    }

    function onExit(code) {
      cleanup();
      reject(new Error(`wsh-server exited early (code ${code}): ${logs.join('')}`));
    }

    function cleanup() {
      clearTimeout(deadline);
      proc.stdout.off('data', checkReady);
      proc.stderr.off('data', checkReady);
      proc.off('exit', onExit);
    }

    proc.stdout.on('data', checkReady);
    proc.stderr.on('data', checkReady);
    proc.once('exit', onExit);
    // In case the listener log line arrived in the same tick data was
    // pushed above (before these listeners were attached).
    checkReady();
  });

  return { proc, url: `wss://127.0.0.1:${port}`, homeDir, logs };
}

async function stopServer(server) {
  if (!server) return;
  server.proc.kill();
  await new Promise((resolve) => {
    if (server.proc.exitCode !== null) return resolve();
    server.proc.once('exit', resolve);
    setTimeout(resolve, 2000); // don't hang the suite if it's slow to die
  });
  rmSync(server.homeDir, { recursive: true, force: true });
}

async function makeKeyPair() {
  const kp = await generateKeyPair(true);
  const publicKeySSH = await exportPublicKeySSH(kp.publicKey);
  return { kp, publicKeySSH };
}

/**
 * Authenticate over QMux by hand (bypassing WshClient), returning a
 * `send`/`waitFor` pair that lets a test craft a protocol-non-compliant
 * message -- e.g. a forged ReverseRegister -- that WshClient itself would
 * never construct. Ported from tools/test/wsh-server.test.mjs's identically-
 * named helper (used there against the Node reimplementation server); here
 * it drives the real Rust binary over its wss:// WebSocket listener instead
 * (NODE_TLS_REJECT_UNAUTHORIZED is already relaxed globally in `before()`
 * above for the self-signed dev cert). Used by the signed-peer-record
 * security tests below (wsh #17), which need to send exactly the wrong
 * thing on purpose.
 */
async function connectRawPeer(url, keys, username) {
  const ws = new WebSocket(url);
  const qmux = new QMuxConnection({ isClient: true, send: (bytes) => ws.send(bytes) });
  // See the identical comment in tools/test/wsh-server.test.mjs's
  // connectRawPeer: route inbound WS messages through SerialQueue so a
  // synchronous burst of 'message' events (e.g. SERVER_HELLO + CHALLENGE
  // arriving in the same underlying socket read) can't silently drop a
  // message whose waiter hasn't been registered yet.
  const inboundQueue = new SerialQueue(async (data) => {
    qmux.receiveBytes(data);
    await Promise.resolve();
  });
  ws.on('message', (data) => inboundQueue.push(new Uint8Array(data)));
  await new Promise((resolve, reject) => {
    ws.once('open', resolve);
    ws.once('error', reject);
  });
  const decoder = new FrameDecoder();
  qmux.sendHandshake();
  const controlStream = await qmux.openStream();

  const waiters = [];
  controlStream.onData = (data) => {
    for (const msg of decoder.feed(data)) {
      const idx = waiters.findIndex((w) => w.type === msg.type);
      if (idx >= 0) { const [w] = waiters.splice(idx, 1); w.resolve(msg); }
    }
  };
  const send = (msg) => controlStream.write(frameEncode(msg));
  const waitFor = (type, timeout = 2000) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timed out waiting for message type ${type}`)), timeout);
    waiters.push({ type, resolve: (m) => { clearTimeout(timer); resolve(m); } });
  });

  send(hello({ username }));
  const serverHelloMsg = await waitFor(MSG.SERVER_HELLO);
  const challengeMsg = await waitFor(MSG.CHALLENGE);
  const { signature, publicKeyRaw } = await signChallenge(
    keys.kp.privateKey, keys.kp.publicKey, serverHelloMsg.session_id, challengeMsg.nonce, { username },
  );
  send(auth({ method: 'pubkey', signature, publicKey: publicKeyRaw }));
  await waitFor(MSG.AUTH_OK);

  return { ws, send, waitFor, publicKeyRaw };
}

/** SHA-256 fingerprint bytes of a running server's self-signed cert, for WebTransport's serverCertificateHashes pinning. */
function certFingerprintBytes(server) {
  const certPath = path.join(server.homeDir, '.wsh', 'cert.pem');
  const fpOutput = execFileSync('openssl', ['x509', '-in', certPath, '-noout', '-fingerprint', '-sha256']).toString();
  const fpHex = fpOutput.split('=')[1].trim();
  return Uint8Array.from(fpHex.split(':').map((h) => parseInt(h, 16)));
}

/**
 * Install a WebTransport global that pins the given server's self-signed
 * dev cert (@johnhenry/wsh's WebTransportTransport calls `new
 * WebTransport(url)` with no options, so pinning has to be injected this
 * way). Returns a restore function — always call it in a `finally`.
 */
async function installPinnedWebTransport(server) {
  await quicheLoaded;
  const fingerprintBytes = certFingerprintBytes(server);
  const original = globalThis.WebTransport;
  globalThis.WebTransport = class extends RealWebTransport {
    constructor(url) {
      super(url, { serverCertificateHashes: [{ algorithm: 'sha-256', value: fingerprintBytes }] });
    }
  };
  return () => {
    if (original === undefined) delete globalThis.WebTransport;
    else globalThis.WebTransport = original;
  };
}

const servers = [];
const clients = [];
afterEach(async () => {
  for (const c of clients.splice(0)) await c.disconnect().catch(() => {});
  for (const s of servers.splice(0)) await stopServer(s).catch(() => {});
});

// ── Auth handshake ──────────────────────────────────────────────────

describe('Rust wsh-server auth handshake', () => {
  it('accepts a client whose key is in authorized_keys, over real TLS WebSocket', async () => {
    const { kp, publicKeySSH } = await makeKeyPair();
    const server = await startServer([publicKeySSH]);
    servers.push(server);

    const client = new WshClient();
    clients.push(client);
    const sessionId = await client.connect(server.url, { username: 'alice', keyPair: kp });
    assert.equal(typeof sessionId, 'string');
    assert.ok(sessionId.length > 0);
  });

  it('rejects a client whose key is not in authorized_keys', async () => {
    const { kp } = await makeKeyPair();
    const other = await makeKeyPair();
    const server = await startServer([other.publicKeySSH]);
    servers.push(server);

    const client = new WshClient();
    clients.push(client);
    await assert.rejects(
      () => client.connect(server.url, { username: 'mallory', keyPair: kp }),
      /Authentication failed/,
    );
  });

  it('completes the full HELLO -> SERVER_HELLO -> CHALLENGE -> AUTH -> AUTH_OK sequence', async () => {
    // The Rust server (crates/wsh-server/src/handshake.rs::handle_hello) always
    // sends SERVER_HELLO before CHALLENGE (never skips it), and @johnhenry/wsh's
    // WshClient.connect() explicitly branches on receiving SERVER_HELLO first
    // (see node_modules/@johnhenry/wsh/src/client.mjs). A successful connect()
    // resolving to a real (non-"pending") session ID is proof this exact path
    // — rather than the "server skipped SERVER_HELLO" fallback — was taken.
    const { kp, publicKeySSH } = await makeKeyPair();
    const server = await startServer([publicKeySSH]);
    servers.push(server);

    const client = new WshClient();
    clients.push(client);
    const sessionId = await client.connect(server.url, { username: 'alice', keyPair: kp });
    assert.notEqual(sessionId, 'pending');
    assert.match(sessionId, /^[0-9a-f]{32}$/);
  });
});

// ── Direct-host exec sessions ───────────────────────────────────────

describe('Rust wsh-server direct-host exec sessions', () => {
  it('runs a command and streams stdout back, then exits 0', async () => {
    const { kp, publicKeySSH } = await makeKeyPair();
    const server = await startServer([publicKeySSH]);
    servers.push(server);

    const client = new WshClient();
    clients.push(client);
    await client.connect(server.url, { username: 'alice', keyPair: kp });

    const session = await client.openSession({ type: 'exec', command: 'echo hello-wsh-rust' });
    // Still 'virtual' here (not 'stream') -- see the wsh #22 PR 3 of 3
    // update in this file's header comment for why this server doesn't
    // make the same switch tools/wsh-server.mjs does.
    assert.equal(session.dataMode, 'virtual', 'exec channels stay on data_mode: virtual against this server (wsh #22 PR 3 of 3)');
    const chunks = [];
    let exitCode = null;
    await new Promise((resolve) => {
      session.onData = (d) => chunks.push(d);
      session.onExit = (c) => { exitCode = c; };
      session.onClose = resolve;
    });

    const text = Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
    assert.match(text, /hello-wsh-rust/);
    assert.equal(exitCode, 0);
  });

  it('reports a non-zero exit code for a failing command', async () => {
    const { kp, publicKeySSH } = await makeKeyPair();
    const server = await startServer([publicKeySSH]);
    servers.push(server);

    const client = new WshClient();
    clients.push(client);
    await client.connect(server.url, { username: 'alice', keyPair: kp });

    const session = await client.openSession({ type: 'exec', command: 'exit 7' });
    let exitCode = null;
    await new Promise((resolve) => {
      session.onExit = (c) => { exitCode = c; };
      session.onClose = resolve;
    });
    assert.equal(exitCode, 7);
  });

  it('runs multiple sequential exec sessions on one authenticated connection', async () => {
    const { kp, publicKeySSH } = await makeKeyPair();
    const server = await startServer([publicKeySSH]);
    servers.push(server);

    const client = new WshClient();
    clients.push(client);
    await client.connect(server.url, { username: 'alice', keyPair: kp });

    for (const [command, expected] of [['echo one', /one/], ['echo two', /two/]]) {
      const session = await client.openSession({ type: 'exec', command });
      const chunks = [];
      await new Promise((resolve) => {
        session.onData = (d) => chunks.push(d);
        session.onClose = resolve;
      });
      const text = Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
      assert.match(text, expected);
    }
  });
});

// ── Real PTY sessions ────────────────────────────────────────────────
//
// This is the capability gap the Node reimplementation (tools/wsh-server.mjs)
// explicitly cannot fill — it has no real PTY backend and rejects `type:
// 'pty'` outright (see tools/test/wsh-server.test.mjs's "rejects kind 'pty'"
// test). The Rust server uses `portable-pty` for real PTYs
// (crates/wsh-server/src/session/pty.rs).

describe('Rust wsh-server real PTY sessions', () => {
  it('opens a pty session, runs a command, and closes with the right exit code', async () => {
    const { kp, publicKeySSH } = await makeKeyPair();
    const server = await startServer([publicKeySSH]);
    servers.push(server);

    const client = new WshClient();
    clients.push(client);
    await client.connect(server.url, { username: 'alice', keyPair: kp });

    const session = await client.openSession({ type: 'pty', command: 'echo pty-hello; exit 3' });
    assert.equal(session.dataMode, 'virtual', 'pty channels stay on data_mode: virtual (unaffected by wsh #22 PR 3 of 3 either way)');
    const chunks = [];
    let exitCode = null;
    await new Promise((resolve) => {
      session.onData = (d) => chunks.push(d);
      session.onExit = (c) => { exitCode = c; };
      session.onClose = resolve;
    });

    const text = Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
    // A real PTY converts bare \n to \r\n (line discipline), unlike a plain
    // pipe — this is PTY-specific behavior a non-PTY exec backend wouldn't
    // produce, and is direct evidence the command ran under an actual PTY.
    assert.match(text, /pty-hello\r\n/);
    assert.equal(exitCode, 3);
  });

  it('accepts stdin written after open (interactive PTY) and echoes it back', async () => {
    const { kp, publicKeySSH } = await makeKeyPair();
    const server = await startServer([publicKeySSH]);
    servers.push(server);

    const client = new WshClient();
    clients.push(client);
    await client.connect(server.url, { username: 'alice', keyPair: kp });

    // `cat` with no args echoes each line of stdin back to stdout verbatim —
    // a simple, deterministic way to prove SessionData flows both
    // client->server (stdin, handled by the new dispatch_message SessionData
    // arm writing to PtyHandle::write_blocking) and server->client (stdout,
    // handled by the new spawn_pty_output_pump).
    const session = await client.openSession({ type: 'pty', command: 'cat' });
    const chunks = [];
    session.onData = (d) => chunks.push(d);

    // Give the PTY a moment to start reading before writing stdin.
    await new Promise((r) => setTimeout(r, 200));
    await session.write(new TextEncoder().encode('echo-back-marker\n'));

    // Poll briefly for the echoed line to show up in stdout.
    const deadline = Date.now() + 5000;
    let text = '';
    while (Date.now() < deadline) {
      text = Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
      if (text.includes('echo-back-marker')) break;
      await new Promise((r) => setTimeout(r, 50));
    }
    assert.match(text, /echo-back-marker/);

    // Send EOF (Ctrl-D) to make `cat` exit cleanly.
    await session.write(new Uint8Array([0x04]));
    await new Promise((resolve) => {
      session.onClose = resolve;
      session.onExit = () => {};
    });
  });
});

// ── WebTransport (QUIC) — listener-level check only ─────────────────
//
// See the file header comment for exactly why this cannot be a full
// end-to-end interop test in plain Node (no global `WebTransport` in Node,
// and @johnhenry/wsh's WebTransportTransport requires one).

describe('Rust wsh-server WebTransport/QUIC listener', () => {
  it('binds the WebTransport (QUIC/UDP) listener and stays healthy at startup', async () => {
    const { publicKeySSH } = await makeKeyPair();
    const server = await startServer([publicKeySSH]);
    servers.push(server);

    assert.ok(
      server.logs.some((l) => l.includes('WebTransport listener started')),
      `expected a "WebTransport listener started" log line, got:\n${server.logs.join('')}`,
    );
    assert.ok(
      !server.logs.some((l) => /panic|WebTransport bind failed/i.test(l)),
      `expected no WebTransport startup errors, got:\n${server.logs.join('')}`,
    );
    assert.equal(server.proc.exitCode, null, 'server process should still be running');
  });

  it('authenticates and runs a direct-host exec session over real WebTransport (QUIC)', async () => {
    const { kp, publicKeySSH } = await makeKeyPair();
    const server = await startServer([publicKeySSH]);
    servers.push(server);

    const restoreWebTransport = await installPinnedWebTransport(server);

    try {
      const wtUrl = server.url.replace(/^wss:\/\//, 'https://');
      const client = new WshClient();
      clients.push(client);
      const sessionId = await client.connect(wtUrl, { username: 'alice', keyPair: kp, transport: 'wt' });
      assert.equal(typeof sessionId, 'string');
      assert.equal(client._transport.constructor.name, 'WebTransportTransport');

      const session = await client.openSession({ type: 'exec', command: 'echo rust-wt-exec-works' });
      const chunks = [];
      let exitCode = null;
      await new Promise((resolve) => {
        session.onData = (d) => chunks.push(d);
        session.onExit = (c) => { exitCode = c; };
        session.onClose = resolve;
      });
      const stdout = Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
      assert.match(stdout, /rust-wt-exec-works/);
      assert.equal(exitCode, 0);
    } finally {
      restoreWebTransport();
    }
  });
});

// ── Relay (reverse-connect) across mixed transports ──────────────────
//
// Mirrors tools/test/wsh-webtransport.test.mjs's "relay reverse-connect
// works across mixed transports" test, but against the real Rust binary
// with --enable-relay instead of the Node reimplementation — the actual
// cross-implementation check for whether the Rust relay (crates/wsh-server/
// src/relay/{broker,registry}.rs, dispatched from server.rs's
// ReverseRegister/ReverseList/ReverseConnect/ReverseAccept arms) speaks the
// same wire protocol @johnhenry/wsh expects, and whether a WebSocket peer and
// a WebTransport operator can be bridged through it.

describe('Rust wsh-server relay — mixed transports', () => {
  it('relay reverse-connect works: WebSocket peer, WebTransport operator', async () => {
    const { kp: operatorKp, publicKeySSH: opPub } = await makeKeyPair();
    const { publicKeySSH: peerPub, kp: peerKp } = await makeKeyPair();

    const server = await startServer([opPub, peerPub], ['--enable-relay']);
    servers.push(server);

    // Peer registers over WebSocket (wss://, self-signed dev cert).
    const peerClient = new WshClient();
    clients.push(peerClient);
    await peerClient.connectReverse(server.url, {
      username: 'browser-tab', keyPair: peerKp, expose: { exec: true }, transport: 'ws',
    });
    peerClient.onReverseConnect = (msg) => {
      peerClient.sendRelayControl(reverseAccept({ targetFingerprint: msg.target_fingerprint, username: 'browser-tab' }));
    };

    // Operator connects over WebTransport and reverse-connects to that peer.
    const restoreWebTransport = await installPinnedWebTransport(server);
    try {
      const wtUrl = server.url.replace(/^wss:\/\//, 'https://');
      const operatorClient = new WshClient();
      clients.push(operatorClient);
      await operatorClient.connect(wtUrl, { username: 'operator', keyPair: operatorKp, transport: 'wt' });
      assert.equal(operatorClient._transport.constructor.name, 'WebTransportTransport');

      const [peerInfo] = await operatorClient.listPeers();
      assert.ok(peerInfo, 'expected the WebSocket peer to be visible to the WebTransport operator via ReverseList/ReversePeers');
      const acceptResponse = await operatorClient.reverseConnect(peerInfo.fingerprint);
      assert.equal(acceptResponse.type, MSG.REVERSE_ACCEPT);
    } finally {
      restoreWebTransport();
    }
  });
});

// ── Relay: signed peer records (wsh #17) ──────────────────────────────
//
// Mirrors tools/test/wsh-server.test.mjs's "WshServer relay — registration
// and discovery" positive control and "WshServer relay — signed peer
// record security" suite, but against the real Rust binary instead of the
// Node reimplementation — the cross-implementation check for whether
// crates/wsh-server/src/server.rs's ReverseRegister arm actually verifies
// signed peer records (wsh_core::verify_peer_record, wsh_core::PeerRecord)
// the same way the Node server's #handleRelayMessage does: the registering
// connection's own authenticated identity (ctx.fingerprint, from AUTH) must
// match the signed record's public_key, the signature must verify, and a
// stale seq must not overwrite a newer registration.

describe('Rust wsh-server relay — registration and discovery', () => {
  it('lists a registered peer via listPeers, and its signed record verifies client-side', async () => {
    const peerKeys = await makeKeyPair();
    const operatorKeys = await makeKeyPair();
    const server = await startServer([peerKeys.publicKeySSH, operatorKeys.publicKeySSH], ['--enable-relay']);
    servers.push(server);

    const peerClient = new WshClient();
    clients.push(peerClient);
    await peerClient.connectReverse(server.url, {
      username: 'browser-tab',
      keyPair: peerKeys.kp,
      expose: { shell: true, exec: true },
    });

    const operatorClient = new WshClient();
    clients.push(operatorClient);
    await operatorClient.connect(server.url, { username: 'operator', keyPair: operatorKeys.kp });
    const peers = await operatorClient.listPeers();

    assert.equal(peers.length, 1);
    assert.equal(peers[0].username, 'browser-tab');
    assert.ok(peers[0].capabilities.includes('shell'));
    assert.ok(peers[0].capabilities.includes('exec'));
    // Client-side verification (listPeers()) of the peer's own signed
    // record must actually pass for a legitimately-registered peer --
    // this is the positive control for the security tests below, and
    // proves the Rust server forwards public_key/seq/record_signature in
    // ReversePeers with byte-identical transcript framing to the JS side.
    assert.equal(peers[0].verified, true);
  });
});

describe('Rust wsh-server relay — signed peer record security (wsh #17)', () => {
  it('rejects (silently drops) ReverseRegister whose public_key does not match the authenticated identity', async () => {
    const peerKeys = await makeKeyPair();
    const otherKeys = await makeKeyPair(); // a real, valid key -- just not the one that authenticated
    const operatorKeys = await makeKeyPair();
    const server = await startServer([peerKeys.publicKeySSH, operatorKeys.publicKeySSH], ['--enable-relay']);
    servers.push(server);

    // Authenticates as peerKeys, then registers claiming otherKeys' public
    // key -- correctly self-signed by otherKeys, so the signature itself
    // is valid; only the identity binding is forged.
    const raw = await connectRawPeer(server.url, peerKeys, 'browser-tab');
    const record = { username: 'browser-tab', capabilities: ['exec'], seq: Date.now() };
    const otherPublicKeyRaw = await exportPublicKeyRaw(otherKeys.kp.publicKey);
    const { signature: recordSignature } = await signPeerRecord(otherKeys.kp.privateKey, otherKeys.kp.publicKey, record);
    raw.send(reverseRegister({ ...record, publicKey: otherPublicKeyRaw, recordSignature }));
    await new Promise((r) => setTimeout(r, 50)); // let the server process (and reject) it

    const operatorClient = new WshClient();
    clients.push(operatorClient);
    await operatorClient.connect(server.url, { username: 'operator', keyPair: operatorKeys.kp });
    const peers = await operatorClient.listPeers();
    assert.equal(peers.length, 0);

    raw.ws.close();
  });

  it('rejects (silently drops) ReverseRegister with a tampered signature', async () => {
    const peerKeys = await makeKeyPair();
    const operatorKeys = await makeKeyPair();
    const server = await startServer([peerKeys.publicKeySSH, operatorKeys.publicKeySSH], ['--enable-relay']);
    servers.push(server);

    const raw = await connectRawPeer(server.url, peerKeys, 'browser-tab');
    const record = { username: 'browser-tab', capabilities: ['exec'], seq: Date.now() };
    const { signature } = await signPeerRecord(peerKeys.kp.privateKey, peerKeys.kp.publicKey, record);
    const tamperedSignature = new Uint8Array(signature);
    tamperedSignature[0] ^= 0xff; // flip a byte -- signature no longer verifies
    raw.send(reverseRegister({ ...record, publicKey: raw.publicKeyRaw, recordSignature: tamperedSignature }));
    await new Promise((r) => setTimeout(r, 50));

    const operatorClient = new WshClient();
    clients.push(operatorClient);
    await operatorClient.connect(server.url, { username: 'operator', keyPair: operatorKeys.kp });
    const peers = await operatorClient.listPeers();
    assert.equal(peers.length, 0);

    raw.ws.close();
  });

  it('rejects a stale re-registration whose seq does not exceed the last accepted one', async () => {
    const peerKeys = await makeKeyPair();
    const operatorKeys = await makeKeyPair();
    const server = await startServer([peerKeys.publicKeySSH, operatorKeys.publicKeySSH], ['--enable-relay']);
    servers.push(server);

    const raw = await connectRawPeer(server.url, peerKeys, 'browser-tab');
    const newer = { username: 'browser-tab', capabilities: ['shell', 'exec'], seq: Date.now() };
    const newerSig = (await signPeerRecord(peerKeys.kp.privateKey, peerKeys.kp.publicKey, newer)).signature;
    raw.send(reverseRegister({ ...newer, publicKey: raw.publicKeyRaw, recordSignature: newerSig }));
    await new Promise((r) => setTimeout(r, 50));

    // A stale record (lower seq, and notably *fewer* capabilities -- this
    // is exactly the "replay to regress capabilities" scenario the seq
    // check defends against) must not overwrite the newer one.
    const stale = { username: 'browser-tab', capabilities: ['exec'], seq: newer.seq - 1000 };
    const staleSig = (await signPeerRecord(peerKeys.kp.privateKey, peerKeys.kp.publicKey, stale)).signature;
    raw.send(reverseRegister({ ...stale, publicKey: raw.publicKeyRaw, recordSignature: staleSig }));
    await new Promise((r) => setTimeout(r, 50));

    const operatorClient = new WshClient();
    clients.push(operatorClient);
    await operatorClient.connect(server.url, { username: 'operator', keyPair: operatorKeys.kp });
    const peers = await operatorClient.listPeers();
    assert.equal(peers.length, 1);
    assert.ok(peers[0].capabilities.includes('shell'), 'the newer record should still be in effect');

    raw.ws.close();
  });
});

// ── File transfer (wsh #13: unified onto FileChunk) ──────────────────
//
// Exercises the Rust server's File-kind channel support (new
// functionality -- it rejected every File-kind Open outright before),
// against files large enough to require multiple 64KB FileChunk messages,
// using the real Rust binary and the real @johnhenry/wsh client.

describe('Rust wsh-server file transfer', () => {
  it('download() reads a real file from the server filesystem, including multi-chunk transfers', async () => {
    const { kp, publicKeySSH } = await makeKeyPair();
    const server = await startServer([publicKeySSH]);
    servers.push(server);

    const remotePath = path.join(server.homeDir, 'download-me.bin');
    const original = Buffer.alloc(200_000);
    for (let i = 0; i < original.length; i++) original[i] = i % 256;
    writeFileSync(remotePath, original);

    const client = new WshClient();
    clients.push(client);
    await client.connect(server.url, { username: 'alice', keyPair: kp });

    const result = await client.download(remotePath);
    assert.deepEqual(Buffer.from(result), original);
  });

  it('upload() writes a real file to the server filesystem, including multi-chunk transfers', async () => {
    const { kp, publicKeySSH } = await makeKeyPair();
    const server = await startServer([publicKeySSH]);
    servers.push(server);

    const client = new WshClient();
    clients.push(client);
    await client.connect(server.url, { username: 'alice', keyPair: kp });

    const remotePath = path.join(server.homeDir, 'upload-target.bin');
    const original = Buffer.alloc(200_000);
    for (let i = 0; i < original.length; i++) original[i] = (i * 7) % 256;

    await client.upload(original, remotePath);

    assert.deepEqual(readFileSync(remotePath), original);
  });

  it('upload() then download() round-trips real content through the real filesystem', async () => {
    const { kp, publicKeySSH } = await makeKeyPair();
    const server = await startServer([publicKeySSH]);
    servers.push(server);

    const client = new WshClient();
    clients.push(client);
    await client.connect(server.url, { username: 'alice', keyPair: kp });

    const remotePath = path.join(server.homeDir, 'roundtrip.txt');
    const original = new TextEncoder().encode('roundtrip through the real Rust wsh-server filesystem');

    await client.upload(original, remotePath);
    const result = await client.download(remotePath);

    assert.deepEqual(result, original);
  });

  it('download() of a nonexistent path fails with OPEN_FAIL, not a hang', async () => {
    const { kp, publicKeySSH } = await makeKeyPair();
    const server = await startServer([publicKeySSH]);
    servers.push(server);

    const client = new WshClient();
    clients.push(client);
    await client.connect(server.url, { username: 'alice', keyPair: kp });

    await assert.rejects(
      () => client.download(path.join(server.homeDir, 'does-not-exist.bin')),
      /Failed to open session/,
    );
  });

  it('upload() to an unwritable path fails cleanly', async () => {
    const { kp, publicKeySSH } = await makeKeyPair();
    const server = await startServer([publicKeySSH]);
    servers.push(server);

    const client = new WshClient();
    clients.push(client);
    await client.connect(server.url, { username: 'alice', keyPair: kp });

    await assert.rejects(
      () => client.upload(new Uint8Array([1, 2, 3]), '/no/such/directory/file.bin'),
      /Failed to open session/,
    );
  });
});

// ── Session management (wsh #14: JS/Rust parity for Detach/SessionList) ──
//
// listRemoteSessions()/detach()/grantSessionAccess()/revokeSessionAccess()
// were newly added to WshClient to close a gap where the Rust client/CLI
// already had this functionality (`wsh sessions`, `wsh detach`) but the JS
// client had no equivalent. Exercised here against the real Rust server to
// verify wire compatibility, not just the JS-side mock in test/client.test.mjs.

describe('Rust wsh-server session management', () => {
  it('listRemoteSessions() sees a session opened on the same authenticated connection', async () => {
    const { kp, publicKeySSH } = await makeKeyPair();
    const server = await startServer([publicKeySSH]);
    servers.push(server);

    const client = new WshClient();
    clients.push(client);
    await client.connect(server.url, { username: 'alice', keyPair: kp });

    const session = await client.openSession({ type: 'exec', command: 'sleep 5' });

    const sessions = await client.listRemoteSessions();
    assert.ok(sessions.some((s) => s.username === 'alice'));

    await session.close();
  });

  it('detach() releases the session without ending it server-side', async () => {
    const { kp, publicKeySSH } = await makeKeyPair();
    const server = await startServer([publicKeySSH]);
    servers.push(server);

    const client = new WshClient();
    clients.push(client);
    await client.connect(server.url, { username: 'alice', keyPair: kp });

    const session = await client.openSession({ type: 'exec', command: 'sleep 5' });
    const [{ session_id: sessionId }] = await client.listRemoteSessions();

    await client.detach(sessionId);

    // The session should still be listed (detach releases control, it
    // doesn't end the session) -- reconnecting and listing again confirms
    // the server kept it alive rather than tearing it down.
    const secondClient = new WshClient();
    clients.push(secondClient);
    await secondClient.connect(server.url, { username: 'alice', keyPair: kp });
    const sessionsAfter = await secondClient.listRemoteSessions();
    assert.ok(sessionsAfter.some((s) => s.session_id === sessionId));
  });
});

// ── Attach/Resume (clawser #48) ────────────────────────────────────
//
// Attach/Resume were entirely unreachable before this fix: no code path
// ever minted a session-scoped HMAC token for a PTY/exec session, so
// verify_token() could never succeed for any caller against any real
// session_id, and both JS/Rust clients additionally sent the wrong
// (connection-level, not session-scoped) token to begin with. Fixed by:
//   1. Open now mints a token alongside the session_id, returned in OpenOk
//      (exposed as WshSession.resumeToken/.sessionId).
//   2. Attach accepts EITHER a valid token OR check_session_access
//      (ownership or a SessionGrant/grantSessionAccess ACL grant) --
//      neither is required on its own. This is the case exercised below:
//      a granted-but-not-owning principal has no way to ever hold the
//      token (only the opener receives one), so ACL access alone must be
//      sufficient for Attach to actually serve SessionGrant's purpose.
//   3. Resume keeps requiring its token unconditionally -- it's for the
//      specific "the credentialed connection that opened this session is
//      coming back" case, not general ACL-based access.
// Also covers the negative control: an authenticated-but-unauthorized
// caller (no ownership, no grant, no token) must still be rejected --
// making Attach reachable must not have made it reachable for everyone.

describe('Rust wsh-server Attach/Resume (clawser #48)', () => {
  it('the session owner attaches from a second connection with no token, relying on ownership alone', async () => {
    const { kp, publicKeySSH } = await makeKeyPair();
    const server = await startServer([publicKeySSH]);
    servers.push(server);

    const owner = new WshClient();
    clients.push(owner);
    await owner.connect(server.url, { username: 'alice', keyPair: kp });
    const session = await owner.openSession({ type: 'exec', command: 'sleep 5' });
    const sessionId = session.sessionId;
    assert.ok(sessionId, 'OpenOk should carry a session_id for an exec channel (clawser #48)');
    assert.ok(session.resumeToken instanceof Uint8Array, 'OpenOk should carry a resume token for an exec channel (clawser #48)');

    const second = new WshClient();
    clients.push(second);
    await second.connect(server.url, { username: 'alice', keyPair: kp });

    const response = await second.attachSession(sessionId);
    assert.equal(response.type, MSG.PRESENCE);

    await session.close();
  });

  it('a principal granted access via grantSessionAccess attaches with no token at all', async () => {
    const alice = await makeKeyPair();
    const bob = await makeKeyPair();
    const server = await startServer([alice.publicKeySSH, bob.publicKeySSH]);
    servers.push(server);

    const ownerClient = new WshClient();
    clients.push(ownerClient);
    await ownerClient.connect(server.url, { username: 'alice', keyPair: alice.kp });
    const session = await ownerClient.openSession({ type: 'exec', command: 'sleep 5' });
    const sessionId = session.sessionId;

    await ownerClient.grantSessionAccess(sessionId, 'bob', ['read', 'write']);

    // bob never received the session's token -- only the opener (alice) did,
    // via OpenOk. This is the exact case Attach's ACL/ownership path exists
    // to serve: a granted principal who was never handed a token.
    const bobClient = new WshClient();
    clients.push(bobClient);
    await bobClient.connect(server.url, { username: 'bob', keyPair: bob.kp });

    const response = await bobClient.attachSession(sessionId);
    assert.equal(response.type, MSG.PRESENCE);

    await session.close();
  });

  it('an unauthorized user (no ownership, no grant, no token) is rejected -- negative control', async () => {
    const alice = await makeKeyPair();
    const mallory = await makeKeyPair();
    const server = await startServer([alice.publicKeySSH, mallory.publicKeySSH]);
    servers.push(server);

    const ownerClient = new WshClient();
    clients.push(ownerClient);
    await ownerClient.connect(server.url, { username: 'alice', keyPair: alice.kp });
    const session = await ownerClient.openSession({ type: 'exec', command: 'sleep 5' });
    const sessionId = session.sessionId;

    const malloryClient = new WshClient();
    clients.push(malloryClient);
    await malloryClient.connect(server.url, { username: 'mallory', keyPair: mallory.kp });

    await assert.rejects(
      () => malloryClient.attachSession(sessionId),
      /not authorized to attach to this session/,
    );

    await session.close();
  });

  it('resumeSession() succeeds for the session opener presenting the OpenOk-issued token', async () => {
    const { kp, publicKeySSH } = await makeKeyPair();
    const server = await startServer([publicKeySSH]);
    servers.push(server);

    const owner = new WshClient();
    clients.push(owner);
    await owner.connect(server.url, { username: 'alice', keyPair: kp });
    const session = await owner.openSession({ type: 'exec', command: 'sleep 5' });
    const sessionId = session.sessionId;
    const token = session.resumeToken;

    const second = new WshClient();
    clients.push(second);
    await second.connect(server.url, { username: 'alice', keyPair: kp });

    const response = await second.resumeSession(sessionId, token);
    assert.equal(response.type, MSG.PRESENCE);

    await session.close();
  });

  it('resumeSession() rejects a tampered/invalid token even from the session owner -- ownership alone is not enough for Resume', async () => {
    const { kp, publicKeySSH } = await makeKeyPair();
    const server = await startServer([publicKeySSH]);
    servers.push(server);

    const owner = new WshClient();
    clients.push(owner);
    await owner.connect(server.url, { username: 'alice', keyPair: kp });
    const session = await owner.openSession({ type: 'exec', command: 'sleep 5' });
    const sessionId = session.sessionId;

    // Flip a byte in an otherwise well-formed (correct-length) token so it
    // fails HMAC verification rather than the length check -- this is the
    // real "wrong credential" case, not just malformed input.
    const badToken = new Uint8Array(session.resumeToken);
    badToken[badToken.length - 1] ^= 0xff;

    const second = new WshClient();
    clients.push(second);
    // Same user, real ownership -- proves Resume doesn't fall back to
    // check_session_access the way Attach does.
    await second.connect(server.url, { username: 'alice', keyPair: kp });

    await assert.rejects(
      () => second.resumeSession(sessionId, badToken),
      /invalid token/,
    );

    await session.close();
  });
});

// ── E2E key exchange relay (wsh #18) ──────────────────────────────
//
// KeyExchange/EncryptedFrame are relayed opaquely by the Rust server
// (dispatch_message's "E2E encryption" arm in server.rs) between whichever
// connections are attached to the same session_id -- it never participates
// in the exchange itself, just forwards. Found while scoping wsh #18's Rust
// side: the relay reconstructed KeyExchangePayload by hand with only
// {session_id, algorithm, public_key}, silently dropping the hybrid
// X25519+ML-KEM-768 fields (kem_public_key/kem_ciphertext) added this
// session -- degrading two JS clients' relayed hybrid E2E exchange to
// classical-only, with neither side any the wiser. Fixed by forwarding the
// whole payload verbatim; this is the regression test for that fix, run
// against the real Rust binary.
//
// Setting up two connections sharing a session_id requires attachSession(),
// which used to hit a separate, pre-existing gap -- crates/wsh-server's
// Attach/Resume handlers required a session-scoped HMAC token
// (wsh_core::token::verify_token) that was never actually minted for
// PTY/exec sessions anywhere server-side, so Attach failed with "invalid
// token signature" for any caller, not just a different identity. Fixed in
// clawser#48: Open now mints a session-scoped token (returned via OpenOk,
// exposed as WshSession.resumeToken) and Attach's authorization is
// satisfied by EITHER a valid token OR check_session_access
// (owner/ACL-granted) -- clientB below attaches purely on the strength of
// being authenticated as the same username as the session's owner, with no
// token at all, exercising exactly that ACL/ownership path. The
// relay-forwarding fix itself was unaffected by clawser#48 and already
// covered by the KeyExchangePayload round-trip unit test in crates/wsh-client.

describe('Rust wsh-server E2E key exchange relay (wsh #18)', () => {
  it('relays a hybrid X25519+ML-KEM-768 KeyExchange between two clients attached to the same session, without dropping the KEM fields', async () => {
    const { kp, publicKeySSH } = await makeKeyPair();
    const server = await startServer([publicKeySSH]);
    servers.push(server);

    const clientA = new WshClient();
    clients.push(clientA);
    await clientA.connect(server.url, { username: 'alice', keyPair: kp });
    const session = await clientA.openSession({ type: 'exec', command: 'sleep 10' });
    const [{ session_id: sessionId }] = await clientA.listRemoteSessions();

    // check_session_access() grants access to any connection authenticated
    // as the session's owning username -- attaching as the same user is
    // enough to get both connections into conn_session_map for this
    // session_id, which is what scopes the relay.
    const clientB = new WshClient();
    clients.push(clientB);
    await clientB.connect(server.url, { username: 'alice', keyPair: kp });
    await clientB.attachSession(sessionId);

    const [resultA, resultB] = await Promise.all([
      clientA.initiateE2E(sessionId, 'X25519+ML-KEM-768'),
      clientB.initiateE2E(sessionId, 'X25519+ML-KEM-768'),
    ]);

    // If the relay had dropped kem_public_key in transit, neither side would
    // see the other's, and both would silently fall back to hybrid: false --
    // this assertion is exactly what the pre-fix relay code would have failed.
    assert.equal(resultA.hybrid, true);
    assert.equal(resultB.hybrid, true);

    // Prove it's the SAME derived key, not just that both independently
    // "succeeded" -- encrypt with A's key, decrypt with B's.
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode('wsh-rust-relay-e2e-probe');
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, resultA.sharedSecret, plaintext);
    const decrypted = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, resultB.sharedSecret, ciphertext));
    assert.deepEqual([...decrypted], [...plaintext]);

    await session.close();
  });
});
