// A Node wsh host for driving the Rust `wsh` CLI in test/rust/wsh-cli.test.mjs.
//
// Configuration arrives as JSON in $WSH_FIXTURE: { authorizedKey: "ssh-ed25519 ...",
// tls?: { cert, key } (PEM strings) }. It prints one line, `LISTENING <port>`, once bound.
//
// The `exec` runner understands a few commands so one host serves every test:
//   echo <text>      write "<text>\n" at once and exit 0 -- the host answers in the same
//                    burst as OpenOk, which is the case #135 is about
//   exit <n>         exit with status n
//   bulk <mib>       write <mib> MiB of output as fast as flow control allows, exit 0
//   head1            echo the first chunk of stdin back as "got:<chunk>" and exit 0 (this host has
//                    no stdin EOF: session data rides control messages)
//   path             print the request path the client connected with
//   wait-signal      wait for a signal and print "signal:<NAME>\n", then exit 0
//   whoami           print the authenticated user
// A pty session runs a fake terminal that prints "ready" and ends by itself after
// $WSH_FIXTURE.ptyMs (default 300 ms), so a client's reaction to the end of a session
// can be tested without a native pty addon.

import { createServer as createHttpsServer } from 'node:https';
import { WebSocketServer } from 'ws';
import { buildAuthorizer, authMethods, FailureLimiter } from '../../../src/server/auth.mjs';
import { buildBackends } from '../../../src/server/backends.mjs';
import { createConnectionFactory } from '../../../src/server/connection.mjs';

const cfg = JSON.parse(process.env.WSH_FIXTURE ?? '{}');

let lastPath = '';
const exec = async (command, io) => {
  const [word, ...rest] = command.trim().split(/\s+/);
  switch (word) {
    case 'echo':
      await io.write(`${rest.join(' ')}\n`);
      return 0;
    case 'exit':
      return Number(rest[0] ?? 0);
    case 'whoami':
      await io.write(`${io.user}\n`);
      return 0;
    case 'bulk': {
      const chunk = new Uint8Array(64 * 1024).fill(0x61);
      const total = Number(rest[0] ?? 1) * 16;
      for (let i = 0; i < total; i += 1) await io.write(chunk);
      return 0;
    }
    case 'head1':
      return new Promise((resolve) => {
        io.onInput(async (bytes) => { await io.write(`got:${Buffer.from(bytes).toString()}`); resolve(0); });
        io.signal.addEventListener('abort', () => resolve(143), { once: true });
      });
    case 'path':
      await io.write(`${lastPath}\n`);
      return 0;
    case 'wait-signal':
      return new Promise((resolve) => {
        io.onSignal(async (name) => { await io.write(`signal:${name}\n`); resolve(0); });
        io.signal.addEventListener('abort', () => resolve(143), { once: true });
      });
    default:
      await io.write(`unknown command: ${command}\n`);
      return 127;
  }
};

const pty = {
  spawn(_file, _args, options) {
    const dataCbs = [];
    const exitCbs = [];
    const timer = setTimeout(() => { for (const cb of exitCbs) cb({ exitCode: 0 }); }, cfg.ptyMs ?? 300);
    setTimeout(() => { for (const cb of dataCbs) cb('ready\r\n'); }, 20);
    return {
      onData: (cb) => dataCbs.push(cb),
      onExit: (cb) => exitCbs.push(cb),
      write() {},
      resize() {},
      kill() { clearTimeout(timer); for (const cb of exitCbs) cb({ exitCode: 0 }); },
      cols: options.cols,
      rows: options.rows,
    };
  },
};

// `createWshServer().listen()` declares exec sessions `data_mode: "stream"`, which the Rust client's
// WebSocket transport does not open (it speaks only the virtual data mode its own server declares). A
// host that carries session data as SessionData -- what an in-page host behind a byte pipe does, and what
// a reverse host does -- is `dataStreams: false`, so the connection factory is driven directly here
// with the same wiring `createWshServer` uses, and a WebSocket listener of our own on top of it.
const log = (line) => { if (process.env.WSH_FIXTURE_LOG) console.error(line); };
const { execRunner, execOptions, pty: ptyConfig } = buildBackends({ exec, pty });
const attach = createConnectionFactory({
  authorize: await buildAuthorizer({ authorizedKeys: cfg.authorizedKey }),
  execRunner, execOptions, pty: ptyConfig, files: null, bindTimeoutMs: 3000, log,
  methods: authMethods({ authorizedKeys: cfg.authorizedKey }), hostKey: null,
  rateLimit: { limiter: new FailureLimiter({}), key: () => 'fixture', failureDelayMs: 0 },
});

let httpsServer = null;
const wss = cfg.tls
  ? new WebSocketServer({ server: (httpsServer = createHttpsServer(cfg.tls)) })
  : new WebSocketServer({ host: '127.0.0.1', port: 0 });
wss.on('connection', (ws, req) => {
  lastPath = req?.url ?? '';
  const conn = attach({
    send: (b) => { if (ws.readyState === 1) ws.send(b); },
    remote: { address: '127.0.0.1', headers: {} },
    dataStreams: false,
    closeTransport: () => ws.close(1000),
  });
  ws.on('message', (d) => {
    const buf = Array.isArray(d) ? Buffer.concat(d) : Buffer.isBuffer(d) ? d : Buffer.from(d);
    conn.receive(new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength));
  });
  ws.on('close', () => conn.close());
  ws.on('error', () => {});
});
await new Promise((resolve) => {
  if (httpsServer) httpsServer.listen(0, '127.0.0.1', resolve);
  else wss.once('listening', resolve);
});
const { port } = (httpsServer ?? wss).address();
console.log(`LISTENING ${port}`);
process.on('SIGTERM', () => process.exit(0));
