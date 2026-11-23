# @johnhenry/wsh

> Previously published as `wsh-upon-star` (last release: 0.1.1, now deprecated).
> Renamed to `@johnhenry/wsh` on import into the @johnhenry family. Unlike
> other packages in this family, wsh did **not** restart its version at
> `0.0.0` on adoption — it was already a mature, actively-depended-upon
> release, so versioning continued forward from there (see
> [CHANGELOG.md](CHANGELOG.md) for the current version). This is a deliberate,
> permanent exception to the family's usual 0.0.0-restart convention, not an
> oversight.

[![npm version](https://img.shields.io/npm/v/%40johnhenry%2Fwsh.svg)](https://www.npmjs.com/package/@johnhenry/wsh)
[![CI](https://github.com/johnhenry/wsh/actions/workflows/ci.yml/badge.svg)](https://github.com/johnhenry/wsh/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/%40johnhenry%2Fwsh.svg)](LICENSE)

Full documentation: [opensource.johnhenry.me/wsh](https://opensource.johnhenry.me/wsh/)

Browser-native remote command execution over WebTransport/WebSocket with Ed25519 authentication.

wsh is a pure-JS client library (with an optional Node server at `@johnhenry/wsh/server`) that connects browsers to remote shells. It implements its own binary protocol — CBOR messages over QMux-multiplexed WebSocket or native WebTransport streams — with Ed25519 challenge-response auth, session management, and MCP tool bridging.

## Contents

- [Install](#install)
- [Features](#features)
- [Wire Protocol: QMux](#wire-protocol-qmux)
- [Quick Start](#quick-start)
- [One-Shot Command Execution](#one-shot-command-execution)
- [Node Server](#node-server)
- [RPC channels (object mode)](#rpc-channels-object-mode)
- [Attach and Resume](#attach-and-resume)
- [Pinning a Self-Signed Certificate](#pinning-a-self-signed-certificate)
- [API Overview](#api-overview)
- [Protocol Specification](#protocol-specification)
- [Rust implementation](#rust-implementation)
- [Security model](#security-model)
- [Browser Compatibility](#browser-compatibility)
- [Browser tests and bundle size](#browser-tests-and-bundle-size)
- [Related projects](#related-projects)
- [Family](#family)
- [License](#license)

## Install

```bash
npm install @johnhenry/wsh
```

Or via CDN:

```html
<script type="module">
  import { WshClient, generateKeyPair } from 'https://esm.sh/@johnhenry/wsh';
</script>
```

## Features

- **Ed25519 authentication** -- challenge-response via Web Crypto API with a transcript binding username and session id, SSH key format support
- **Dual transport** -- WebTransport (native streams) and WebSocket (QMux-multiplexed streams) with identical API
- **Self-signed certificate pinning** -- `serverCertificateHashes` on the WebTransport path, so page JavaScript can reach a server whose certificate no certificate authority signed
- **CBOR encoding** -- compact binary wire format with length-prefixed framing
- **Session management** -- open, attach, resume, detach, rename PTY/exec sessions, with session-scoped resume tokens and per-principal access grants
- **Reverse mode** -- register as a peer (via a signed peer record) and accept incoming connections through a relay
- **File transfer** -- scp-like upload/download as `FileChunk` control messages in 64KB chunks
- **MCP bridge** -- discover and invoke remote MCP tools through the control channel
- **Session recording** -- own JSON schema (asciicast-v2-shaped, not a playable asciicast file -- see note below) recording and playback with seek/pause/resume
- **Key management** -- IndexedDB storage with OPFS encrypted backup (PBKDF2 + AES-256-GCM)
- **105 message types** -- handshake, channel, gateway, guest sharing, compression negotiation, copilot, policy, authorized-key management, and more

> **Session recording is asciicast-v2-shaped, but not an asciicast file.**
> The JS `SessionRecorder.toJSON()` export borrows asciicast v2's vocabulary --
> `version: 2`, `width`, `height`, `timestamp`, `env`, and events as
> `[seconds, "o" | "i" | "r", data]` -- so it is easy to convert, but it is not
> something `asciinema play` can read as-is:
>
> - it is **one JSON document** with an `events` array; asciicast v2 is
>   newline-delimited JSON (a header line, then one event per line);
> - the header carries wsh's own `sessionId`, and `width`/`height` follow the
>   latest resize rather than the size at the start;
> - session lifecycle events (`open`, `exit`) use codes asciicast v2 does not
>   define (the Rust recorder also has `Start`/`Exit`/`Snapshot`, and uses a
>   different, incompatible schema from the JS one);
> - `RecordingExport`'s `format: "asciicast"` option is accepted on the wire but
>   not implemented server-side -- it returns the same custom JSONL as
>   `format: "jsonl"`.
>
> To play a JS recording in asciinema, write the header and the `o`/`i`/`r`
> events out as lines (lossy: lifecycle events are dropped):
>
> ```js
> const { version, width, height, timestamp, env, events } = recorder.toJSON();
> const cast = [JSON.stringify({ version, width, height, timestamp, env }),
>   ...events.filter((e) => 'oir'.includes(e[1])).map((e) => JSON.stringify(e))].join('\n') + '\n';
> // write `cast` to session.cast, then: asciinema play session.cast
> ```
>
> A first-class `.cast` exporter is not provided; the conversion above is the
> supported path (it is covered by `test/recording-format.test.mjs`).

## Wire Protocol: QMux

Over WebSocket, wsh multiplexes streams with QMux (draft-ietf-quic-qmux-02):
QUIC-v1 frames -- RFC 9000 varints, STREAM, RESET_STREAM, STOP_SENDING,
MAX_DATA/MAX_STREAM_DATA/MAX_STREAMS, CONNECTION_CLOSE, DATAGRAM, plus
RESET_STREAM_AT from draft-ietf-quic-reliable-stream-reset -- carried in
self-delimiting Records over the ordered, reliable WebSocket byte stream.
The control channel is QMux stream 0, and every stream gets QUIC-style
windowed flow control, so a slow consumer exerts real backpressure.
`QMuxConnection` and the frame codec primitives are exported so alternate
server implementations can speak the same framing.

## Quick Start

```js
import { WshClient, generateKeyPair } from '@johnhenry/wsh';

// Generate an Ed25519 key pair. Non-extractable (the default): this page's code can sign with the private key
// but nothing can read it out. Authorize it on the host by exporting the PUBLIC half
// (`exportPublicKeySSH(keyPair.publicKey)`); keep keys across reloads with `WshKeyStore`.
const keyPair = await generateKeyPair();

// Connect to a wsh server
const client = new WshClient();
const sessionId = await client.connect('wss://shell.example.com', {
  username: 'alice',
  keyPair,
  transport: 'ws',
});

// Open a PTY session
const session = await client.openSession({
  type: 'pty',
  command: '/bin/bash',
  cols: 120,
  rows: 40,
});

// Handle output
session.onData = (data) => {
  const text = new TextDecoder().decode(data);
  process.stdout.write(text);
};

// Write input
await session.write('echo hello world\n');

// Resize the terminal
await session.resize(160, 50);

// Close when done
await session.close();
await client.disconnect();
```

## One-Shot Command Execution

```js
import { WshClient, generateKeyPair } from '@johnhenry/wsh';

const keyPair = await generateKeyPair(); // non-extractable; see Quick Start
const { stdout, exitCode } = await WshClient.exec(
  'wss://shell.example.com',
  'ls -la /tmp',
  { username: 'alice', keyPair }
);

console.log(new TextDecoder().decode(stdout));
console.log('Exit code:', exitCode);
```

`exec` and `openSession({ type: 'exec' })` need no extra step to receive
output. Older hosts only discover the client-opened data stream once a byte
arrives on it, so against a host that does not advertise `stream-announce`
the client writes a one-byte primer for you (a host that strips it, as those
hosts do). Pass `primer: false` to never send it.

### Stdin and EOF

`stdin` feeds the command and then closes its write side, so `cat`, `wc -c` and `sh -s` finish:

```js
const { stdout } = await WshClient.exec(url, 'wc -c', { username, keyPair, stdin: new Uint8Array(1000) });
// stdin: a string, a Uint8Array, a ReadableStream, or an (async) iterable of strings / bytes
```

On an open exec session, `await session.write(data); await session.closeStdin()` sends EOF without closing the
session: output keeps arriving and `onExit` / `onClose` fire as usual. Without `stdin`, `exec` never touches stdin.

EOF is either the end of the session's stdin data stream (a **stream-mode** host: `@johnhenry/wsh/server`, any
version) or, on a virtual-mode host, a zero-length `SessionData`. The Rust `wsh-server` from `rust-v0.5.0` supports the
second form: it advertises the `exec-pipes` feature, and a client that sees it opens the exec channel with
`stdio: 'pipes'` (`exec({ stdin })` does this by itself), so the command runs on plain pipes -- byte-exact input, no
echo, stderr kept apart (`session.onStderr`, and `stderr` in the `exec()` result) -- and `closeStdin()` works. Against
an older Rust server (no `exec-pipes`; its exec is a PTY) nothing is sent that it would reject, and `closeStdin()` /
`exec({ stdin })` fail with a clear error instead of hanging. `exec` without `stdin`, `pty` sessions and shells keep
the PTY.

## Node Server

`@johnhenry/wsh/server` is a Node host for the same protocol, over WebSocket
(QMux) and, optionally, [WebTransport](#webtransport-listener). It is a separate subpath -- the package root stays browser-safe and
never imports it -- and needs the optional peer dependency `ws`
(`npm install ws`).

```js
import { createWshServer } from '@johnhenry/wsh/server';
import { readFileSync } from 'node:fs';

const server = createWshServer({
  host: '127.0.0.1',
  port: 4422,                                          // 0 = pick a free port
  auth: { authorizedKeys: readFileSync('authorized_keys', 'utf8') },  // ssh-ed25519 lines
  hostKey: { file: '/etc/wsh/host_key' },              // advertise a pinnable host identity (created 0600 on first start)
  exec: true,                                          // opt in: run commands via /bin/sh
  fs: { root: '/srv/share', readOnly: false },         // opt in: list/stat/read/write/rename/mkdir/remove/upload/download
  // pty: { spawn: nodePty.spawn },                    // opt in: bring your own node-pty
});
const { port } = await server.listen();                // later: server.address(), await server.close()
```

Everything that touches the machine -- `exec`, `pty`, `fs` -- is **off unless
you pass it**, and with no `auth` every connection is refused. `auth` is
`{ authorizedKeys, authorize, password, rateLimit }` (a key must be on the
list and pass `authorize({ username, fingerprint, publicKey })` when both are
given) or just an `authorize` function. `exec` can also be `{ cwd, env,
shell, timeoutMs, clientEnv }` or a custom `run(command, io)` for a
restricted host with no shell. `fs.root` confines every path: `..`, absolute
paths and symlinks pointing out of it are refused -- for `write` and `rename`
(both paths) exactly as for `read`.

**Client environment (`clientEnv`).** A client may ask for environment
variables with `openSession({ env })`. Since 0.36 the host accepts only
`TERM`, `COLORTERM`, `LANG`, `LANGUAGE` and `LC_*` by default (the shape of
sshd's `AcceptEnv`); `PATH`, `LD_PRELOAD`, `BASH_ENV` and the like are dropped,
because they change what a shell or a restricted runner executes. Set
`exec: { clientEnv: true }` to accept everything (the old behaviour),
`false` for nothing, a list (`['TERM', 'LC_*', 'MY_APP_TOKEN']`, replacing the
default list) or a predicate `(name, value) => boolean`; `pty: { clientEnv }`
takes the same. At most 64 variables of at most 4096 bytes with plain names
are looked at. **This is a breaking default** for a host that relied on clients
setting arbitrary variables.

**Connection lifetime (`connectionTtlMs`).** `AuthOk` carries a `token` and a
`ttl`. The token is an opaque per-connection value that nothing accepts back
(session resume uses its own per-session token); it stays on the wire because
released clients require the field. `ttl` is now true: `connectionTtlMs: n`
ends every authenticated connection `n` ms after login and advertises it
(`client.authTtl`, whole seconds, rounded up); without it the host promises no
limit and sends `ttl: 0`. Before 0.36 it sent an unenforced 3600. The Rust
`wsh-server` still sends its `session_ttl` setting unenforced.

### Gateway (TCP and DNS egress from the host)

`gateway: { allow: ['broker.lan:1883'], allowPrivate: ['10.0.0.0/8'], socks: '127.0.0.1:9050' }` makes the Node server
answer the gateway opcodes, so a client (a browser tab via netway's `GatewayBackend`, or `client.openTcp()`) can open TCP
connections and resolve names from the host. Default deny; `allow` takes `"*"`, `"host"` or `"host:port"`. `socks` routes
every dial through a SOCKS5 proxy (Tor) with the name unresolved. TCP reverse tunnels are refused. `OpenUdp` is served
(`client.openUdp(host, port)`: one chunk is one datagram, same destination policy, idle flows closed after `udpIdleMs`,
default 60 s, not available through `socks`), but over the reliable control stream: it is ordered and retransmitted, and a
datagram the client cannot take fast enough is dropped by the host. **WebTransport datagrams (the real UDP semantics) are
not implemented yet (#124).**

**The address is checked, not just the name.** The host resolves a name once, refuses every resolved address that is not
globally routable (loopback, private, link-local, CGNAT, ULA, multicast, reserved, and IPv4 addresses wrapped as
IPv4-mapped, NAT64 or 6to4 IPv6), and connects to the address it checked, so a name that resolves to something else a
moment later cannot redirect the connection. Reaching private space is an explicit rule: `allowPrivate` (CIDR blocks or
addresses) for names and `"*"`, or an `allow` entry that is itself an IP literal (`"127.0.0.1:1883"`), which permits
exactly that address. `ResolveDns` answers are filtered with the same rule. Through `socks` the proxy resolves the name,
so only IP literals can be checked there. See the Security model below and the CHANGELOG (this is a behaviour change).

**Flow control.** Gateway data is metered in both directions when both ends offer the `gateway-credit` feature: each
direction of each connection starts with 256 KiB of credit that the receiver tops up (`GatewayCredit`) as its
application consumes data, so a slow reader stops its peer (the origin socket is paused, `write()` results and `drain`
are honoured) instead of making the host buffer. Against a peer without the feature the host still holds the origin back
by the transport's own backpressure and bounds what a client can make it hold with `maxBufferedBytes` (default 4 MiB per
connection) and `maxClientBufferedBytes` (default 32 MiB per client), closing a connection that exceeds them.

#### Unix-domain sockets (streamlocal) and named endpoints

Modelled on OpenSSH's streamlocal forwarding. Off unless configured:

```js
createWshServer({ auth, gateway: {
  allow: [],
  unix: {
    connect: ['/var/run/docker.sock'],          // OpenUnix: a client may connect to these (exact path, or "/dir/" prefix, or "@abstract")
    listen: ['/run/user/1000/wsh/'],             // ListenUnix: a client may ask the host to create sockets under here
    replaceStale: false,                         // a client may replace a STALE socket file only if it asks AND this is true
  },
  endpoints: { ping: async (duplex, who) => { /* ... */ } },   // named virtual endpoints, below
} });
```

Paths are checked after `realpath` of the parent directory (so `/var/run` and `/private/var/run` agree and a symlinked
directory cannot lead out of an allowed one), a `..` segment is refused, and the file must be a socket and not a symlink.
The abstract namespace (`@name`) is refused unless listed. Sockets the host creates are mode `0600` (the umask is
tightened while binding) and are unlinked when the listener closes or the connection ends; an existing socket file is
replaced only when the request says `replace` AND `replaceStale` is on AND nothing accepts connections on it, and a file
that is not a socket is never touched. Allow only directories no other local user can write to: the check cannot close
the instant between it and the connect.

```js
const duplex = await client.openUnix('/var/run/docker.sock');       // web streams with backpressure
await duplex.writable.getWriter().write(new TextEncoder().encode('GET /containers/json HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n'));
// Node: ssh -L / -R shapes, unix and TCP ends mixed
await client.forwardUnix({ local: '127.0.0.1:2375', remote: '/var/run/docker.sock' });     // -L 127.0.0.1:2375:/var/run/docker.sock
await client.forwardUnix({ local: '/tmp/docker.sock', remote: '/var/run/docker.sock' });
await client.forwardUnix({ reverse: true, remote: '/run/user/1000/wsh/app.sock', local: '127.0.0.1:8080' }); // -R
```

**Named virtual endpoints** are for a host with no file system (the memory host, a browser tab):
`endpoints: { docker: (duplex, who) => ... }` registers handlers and a client reaches one with `client.openEndpoint('docker')`.
It is its own message (`OpenEndpoint { name }`) rather than a reserved `OpenUnix` path so that a name can never be
mistaken for (or smuggled as) a file-system path or an abstract-namespace name, and so a host's file-system policy is not
consulted for it; the registered names are an allow-list by construction. `who` is the authenticated
`{ username, fingerprint }`, so the embedder can authorise per call (throw to refuse, or `{ open, authorize(who) }`).

**Rust side: JS only for now.** `wsh-server` does not advertise `gateway-unix`, `gateway-endpoints` or `gateway-credit`,
and `wsh` has no `-L` / `-R` with unix sockets yet. What it must implement: `OpenUnix { gateway_id, path }` and
`ListenUnix { listener_id, path, replace? }` (answer with the existing `GatewayOk`/`GatewayFail` and `ListenOk` with
`actual_port: 0`/`ListenFail`; accepted connections announced with `InboundOpen` and answered by `InboundAccept`'s
`gateway_id`), the same path policy and `0600`/unlink rules, `GatewayCredit` (256 KiB initial credit per direction when
the client's `Hello.features` lists `gateway-credit`), and in the CLI `-L [bind:]port:/remote.sock`,
`-L /local.sock:/remote.sock`, `-R /remote.sock:host:port` and `-R /remote.sock:/local.sock`.

### TLS (`wss://`) and host extensions

`tls: { cert, key }` (PEM, the options of `https.createServer`) serves the WebSocket listener over TLS on the same
port. `extensions: { [type]: (msg, { username, fingerprint, send }) => void }` handles application-defined control
messages whose `type` is a string, from authenticated connections only. On a relay,
`relay: { onUnreachable(from, targetFingerprint, request) }` is told when an operator asked for a peer that is not
registered (the operator still gets `no such peer`), so the host can reach that peer another way, such as a Web Push.

### Pre-upgraded transports: `accept()`

`createWshServer()` normally opens its own listener. If your application already owns the HTTP server (or Worker, or
test harness) and has upgraded the connection itself, hand the socket over instead of bridging it to a per-session
loopback listener (which any local process could also connect to):

```js
const wsh = createWshServer({ auth: { authorizedKeys }, exec: true });   // no listen()
wss.on('connection', (ws, req) => wsh.accept(ws, { remote: { address: req.socket.remoteAddress } }));
```

`accept(socket, { remote })` takes any WebSocket-like duplex (`send`, `close`, `readyState`, and `on` or
`addEventListener`): a `ws` socket, a browser/Worker `WebSocket`, a test double. It applies the same auth, features,
rate limit and session registry as `listen()`'s connections, may be mixed with `listen()`, and resolves to
`{ close() }`. `remote.address` keys the password-failure throttle (sockets without one share a key). `server.close()`
drops every accepted socket.

### In-memory host (`@johnhenry/wsh/memory`)

A browser-safe host for demos and tests: no sockets, no ports, no Node (nothing in its import graph is `node:*` or `ws`).

```js
import { createMemoryHost } from '@johnhenry/wsh/memory';

const host = createMemoryHost({
  auth: { authorizedKeys: [rawPublicKey] },                       // same shapes as createWshServer
  exec: async (command, io) => { await io.write(`ran ${command}\n`); return 0; },
});
const client = await host.connect({ username: 'demo', keyPair });   // or { signer } / { password }
const session = await client.openSession({ type: 'exec', command: 'hi' });
session.onData = (d) => console.log(new TextDecoder().decode(d));   // "ran hi"
```

It is the real connection handler speaking QMux over an in-memory socket pair, so the client code you test is the code
you ship. `host.createClient()` / `host.WebSocket` / `host.accept(socket)` / `createSocketPair()` are the lower-level pieces.
Supported: `auth`, `exec` (a function; there is no shell), `pty`, `fs` and `hostKey` (injected, below), `mcp`,
`extensions`, `rpc`, `sessions` (below) and `endpoints` ([named virtual endpoints](#unix-domain-sockets-streamlocal-and-named-endpoints):
`endpoints: { api: (duplex, who) => ... }`, reached with `client.openEndpoint('api')`, with flow control). Not available
in memory: the TCP, DNS, UDP and unix-socket parts of `gateway`, `relay`, WebTransport, `exec: true` and
`fs: { root }` (they need Node) and the `wsh-host` / `wsh-fs` rpc built-ins (use `@johnhenry/wsh/server`).

**Injected backends**, shaped like the Node host's, so a page can be a real host (#114):

- `pty: { spawn, shell?, cwd?, env?, term? }` -- `spawn` is `node-pty`'s `spawn(file, args, { name, cols, rows, cwd, env })`
  or anything shaped like it, returning `{ onData(cb), onExit(cb), write(data), resize(cols, rows), kill(signal?) }`.
  `write` receives a `Uint8Array` (there is no `Buffer` in a browser, and none is needed anywhere in the host). `shell` is
  the `file` your `spawn` is called with (default `/bin/sh`).
- `fs: { operate, readWhole, writeWhole, writeAt, openRange?, maxFileBytes? }` -- an object of operations, **not** a root path
  (`fs: { root }` needs Node and is refused here). The types are `WshFileBackend` in `@johnhenry/wsh/host`; the file
  operations (`list`, `stat`, `read`, `write`, `rename`, `mkdir`, `remove`) reach `operate` with the path exactly as the
  client sent it, so **confining paths is the backend's job** -- see [Security model](#security-model).
- `hostKey` -- a `CryptoKeyPair` (generate it with `generateKeyPair()` and the private key stays non-extractable), a signer
  `{ publicKey, sign(data) }` for a key held elsewhere, or `true` for a fresh non-extractable key. Clients pin it as for
  any host ([Host key](#host-key-fingerprint--tofu)); the proof is signed through `sign`, so the key never has to be readable.
- `dataStreams` (default `true`) -- whether to offer client-opened QMux data streams. **Set it to `false` for a peer that
  cannot open them: the released Rust client over WebSocket** (`wsh`, `rust-v0.6.0`: "WebSocket transport does not support
  real data streams for this server", #132). Exec output then rides `SessionData` (`data_mode: "virtual"`, as over a relay
  bridge) and `stream-announce` and `rpc` are not offered. It is an option rather than a negotiation because no released
  client says whether it can open streams: the Rust client's `Hello` carries only `mcp` and `file-transfer`. The JS client works
  either way. `host.accept(socket, { dataStreams })` overrides it per connection.

**Serving a socket you opened yourself:** `host.accept(new WebSocket(url))` works on a socket that is still connecting (the
host's first bytes are held until it opens). `accept()` of an in-page host through a relay or a byte pipe is what the
[browser suite](#browser-tests-and-bundle-size) runs against the released Rust CLI.

**`rpc`** takes handler functions only, `rpc: { calc: (channel, ctx) => channel.onRequest('add', ({ a, b }) => a + b) }`
(the `RpcChannel` is the one `@johnhenry/wsh/server` hands its handlers), with `rpcMaxMessageBytes` (default 1 MiB) and
`rpcMaxInflight` (default 64). Clients use `client.openRpc('calc')` unchanged.

**`sessions`** (`true` or `{ detachTtlMs, maxDetached, ringBytes }`) keeps *exec* sessions alive across a dropped link
or `client.detach()`, so `resumeSession()` / `attachSession()` work unchanged: the same Attach / Resume / Detach
messages, `seq` counted in output bytes, and the same errors (unknown or expired session, bad token, `last_seq` ahead
of the session, an output gap). The limits and defaults are the server's: 300000 ms detached before a session is
dropped, at most 16 detached sessions (the longest-detached is dropped first), 1 MiB of replayable output per session
(a resume older than the ring is refused as a gap; `attachSession` gets the retained tail). The session list lives in
the page's memory, so it ends with the page or `host.close()`. Differences from the server: no `sessionSecret` (tokens are random per session instead of HMAC-signed, so they cannot be checked across restarts), and
the host still runs no command by itself: sessions only wrap whatever `exec` function you pass.

### Browser entry points, the connection factory and bundle size

Every `exports` entry except `./server` is browser-safe: no `node:*` import and no `Buffer` is reachable from it (a test
bundles each one for the browser and fails if one is, `test/browser-bundle.test.mjs`), and `"sideEffects": false` lets a
bundler drop what you do not use.

| Entry | What it is |
|---|---|
| `@johnhenry/wsh` | the client (`WshClient`, `WshKeyStore`, ...) |
| `@johnhenry/wsh/memory` | `createMemoryHost()`, a host in this realm (above) |
| `@johnhenry/wsh/host` | the pieces under it, for your own transport: `createConnectionFactory(config)` -- the connection handler `createWshServer`, `createMemoryHost` and `createReverseHost` all run -- plus `bindSocket(socket, ready, { dataStreams })`, `resolveBackends()`, `resolveHostKey()`, `buildAuthorizer()` and `authMethods()`. It does not import the client |
| `@johnhenry/wsh/reverse` | `createReverseHost()` for a page or Worker: dial out to a relay and serve the operator it bridges. The same function `@johnhenry/wsh/server` exports, minus `exec: true` and `fs: { root }` |
| `@johnhenry/wsh/server` | Node only |

```js
import { createConnectionFactory, bindSocket, resolveBackends, buildAuthorizer, authMethods } from '@johnhenry/wsh/host';

const auth = { authorizedKeys: [rawPublicKey] };
const attach = createConnectionFactory({                      // authorize is required: there is no open default
  authorize: await buildAuthorizer(auth), methods: authMethods(auth),
  ...resolveBackends({ exec: async (command, io) => { await io.write('hi\n'); return 0; } }),
});
await bindSocket(upgradedSocket, Promise.resolve(attach), { dataStreams: false });   // or attach({ send, ... }) on a byte pipe
```

`npm run size` prints raw and gzip bytes per entry point (and a few single-import probes, which show tree-shaking at
work) against `scripts/bundle-budget.json`; CI runs it and `npm test` fails a bundle more than 10% over its budget.
`npm run size -- --update` rewrites the budget after a deliberate change. Sizes are of this package's own code:
`@noble/post-quantum`, the optional ML-KEM backend, is left out of the measurement.

### Signing with a page-held signer

`connect()`, `WshClient.exec()` and `connectReverse()` take `signer: { publicKey, sign(data) }` instead of `keyPair`
(not both): `publicKey` is the raw 32-byte Ed25519 key or a public `CryptoKey`, `sign` returns the 64-byte signature
(sync or async). For keys that live in a wallet, a hardware token or another realm and are not a `CryptoKeyPair`.

### WebTransport listener

The client's ladder prefers WebTransport (`https://`) and falls back to `wss://`;
`webTransport` gives the Node host the first rung, with real independent QUIC
streams (no head-of-line blocking across channels):

```js
const server = createWshServer({
  auth, exec: true, fs: { root: '/srv/share' },
  webTransport: { port: 4433, selfSigned: true },        // or { cert, privKey } PEM
});
await server.listen();                                    // the WebSocket listener still runs
const { url, certificateHash } = server.webTransport();  // https://127.0.0.1:4433/wsh, sha-256 of the cert

// client (a browser, or Node with a WebTransport implementation)
await client.connect(url, {
  username, keyPair, transport: 'wt',
  webTransport: { serverCertificateHashes: [{ algorithm: 'sha-256', value: certificateHash }] },
});
```

- **Optional peers**, imported only when `webTransport` is set:
  `npm install @fails-components/webtransport @fails-components/webtransport-transport-http3-quiche`
  (a native HTTP/3 build, prebuilt for Linux/macOS/Windows on x64 and arm).
  Without them `listen()` rejects with that instruction, and a server with no `webTransport`
  never loads them.
- **Same host, other wire.** Auth (keys, password, host key), `exec`, `pty`, `fs`, `mcp`,
  `sessions` and `relay` behave identically; only the transport differs. The control stream is the
  session's first bidirectional stream (length-prefixed CBOR frames); every bidirectional stream the client
  opens afterwards is a data stream, bound to the next exec channel in `OpenOk` order. A client-created
  stream is visible to the host as soon as it exists, so the host advertises `stream-announce` and the
  client writes no primer.
- **`selfSigned: true`** generates (no dependency) an ECDSA P-256 certificate valid for 13 days -- a browser refuses a
  pinned certificate valid for more than 14 -- and exposes the SHA-256 for `serverCertificateHashes`
  (`{ selfSigned: { hosts, validityDays } }` to change the SANs or the lifetime). A certificate you pass as
  `cert`/`privKey` is used as is (`certificateHash` is then `null`, and nothing rotates).
  `generateSelfSignedCertificate()` is exported for the same certificate without a server. The web platform's other
  pinning rules apply (`https:` URL, HTTP/3 only; see
  [Pinning a Self-Signed Certificate](#pinning-a-self-signed-certificate)). **It is rotated, see below.**
- Node has no `WebTransport` global: a Node *client* needs `globalThis.WebTransport = (await import(
  '@fails-components/webtransport')).WebTransport` first. UDP, so a firewall must allow `port`, and there
  is no `wss://`-style TLS terminator in front: the certificate is the one this process serves.
- Tests (`test/server-webtransport.test.mjs`) run the stock client against it over a real HTTP/3
  connection and are **skipped, with the reason, where the native binary cannot load**.

#### Certificate rotation

A pinned certificate cannot just be renewed in place: clients hold its hash, and the platform
takes none valid for more than 14 days. So a `selfSigned` certificate is rotated **ahead of its expiry, with an
overlap in which both hashes are published**:

```js
server.certificateHashes();       // [{ algorithm: 'sha-256', value }, ...]: what a client should pin right now
await server.rotateCertificate(); // make the next certificate now and publish its hash too -> [current, next]
await server.rotateCertificate({ activate: true });   // ... and switch the listener to it immediately
```

- **Automatically**: `prepareBeforeMs` before `notAfter` (default 3 days, at most a third of the validity) the next
  certificate is generated and `certificateHashes()` becomes `[current, next]`; `activateBeforeMs` before `notAfter`
  (default 1 hour, at most a sixth) the listener switches to it and the list drops the old hash. Then the next rotation
  is scheduled from the new certificate. `selfSigned: { rotate: false }` turns this off (restart before `notAfter`,
  as before); `{ prepareBeforeMs, activateBeforeMs, validityDays }` tune it (tests use a seconds-long validity).
  The same list is on `server.webTransport().certificateHashes()`, with validity and which one is active in
  `.certificates()`; `certificateHash`/`notAfter` there always describe the certificate being presented.
- **The switch restarts the HTTP/3 listener on the same port.** The native transport has no way to swap a certificate
  in place and presents one certificate at a time, so live WebTransport sessions end at the switch (the WebSocket
  listener is untouched) and clients reconnect. A client that pinned the overlap list `[current, next]` before the
  switch connects after it; one that only has the old hash does not, so it must **re-pin**.
- **Client re-pin flow.** `serverCertificateHashes` takes several values, and `connect()` / `WebTransportTransport` pass the
  whole array. Publish `server.certificateHashes()` over something the client already trusts (your page's
  HTTPS, an API call, a config endpoint) and have the client fetch it (a) before connecting and (b) again whenever
  the WebTransport handshake fails, then retry once:

  ```js
  // server: GET /wsh-pins -> hex strings (parseCertificateHash() on the client accepts hex)
  app.get('/wsh-pins', (req, res) => res.json(server.certificateHashes().map((h) => Buffer.from(h.value).toString('hex'))));

  // client
  async function connectPinned(url, opts) {
    for (let attempt = 0; ; attempt++) {
      const pins = (await (await fetch('/wsh-pins')).json()).map((hex) => ({ algorithm: 'sha-256', value: hexToBytes(hex) }));
      try { return await client.connect(url, { ...opts, transport: 'wt', webTransport: { serverCertificateHashes: pins } }); }
      catch (err) { if (attempt === 1) throw err; }   // stale pins: fetch the list again and retry once
    }
  }
  ```

  Because the next hash is published `prepareBeforeMs` (3 days) before the switch, a client that refreshes at least that
  often (or on any failure) never sees a certificate it has not pinned. A client that stays up for longer than a certificate
  lives and never refetches needs this retry; `transport: 'wt'` makes the failure explicit instead of falling back to
  `wss://`.
- Not covered: a certificate you supply (`cert`/`privKey`) is yours to renew; restart the server (or run it behind a
  CA-issued certificate, which needs no pinning).

- Node has no `WebTransport` global: a Node *client* needs `globalThis.WebTransport = (await import(
  '@fails-components/webtransport')).WebTransport` first. UDP, so a firewall must allow `port`, and there
  is no `wss://`-style TLS terminator in front: the certificate is the one this process serves.
- Tests (`test/server-webtransport.test.mjs`) run the stock client against it over a real HTTP/3
  connection and are **skipped, with the reason, where the native binary cannot load**.

### Relay / reverse mode

A host that cannot accept connections (behind NAT, or a browser tab) dials *out*
and registers; an operator reaches it through a relay. `@johnhenry/wsh/server`
is both ends:

```js
// The relay -- anyone who can reach it and authenticate; nothing is permitted by default.
createWshServer({
  auth: { authorizedKeys },
  relay: {
    canRegister: (who, record) => who.username === 'build-box',          // who may be a peer
    canConnect: (from, to) => from.username === 'alice',                  // who may list and reach which peer
  },
});

// The peer, on the machine behind the NAT: same backends as createWshServer.
const host = createReverseHost({
  url: 'wss://relay.example/', username: 'build-box', keyPair,
  exec: true, fs: { root: '/srv/share' }, mcp: { tools },
  accept: ({ fingerprint, username }) => fingerprint === aliceFingerprint, // default: nobody
});
await host.start();                    // host.fingerprint is what operators connect to

// The operator: stock client.
const peers = await client.listPeers();                       // each entry's signed record verified client-side
await client.reverseConnect(peers[0].fingerprint);            // ReverseAccept trusts the peer for RelayForward
const s = await client.openSession({ type: 'exec', command: 'echo hello' });
```

- **Default deny, twice.** The relay admits no peer (`canRegister`) and lets no
  one connect (`canConnect`) unless you say so, and the peer refuses every
  operator unless `accept` says otherwise -- the client's `trustRelayPeer()` is
  the third gate. A peer an operator may not connect to is not listed and is
  indistinguishable from an absent one (`ReverseReject: no such peer`).
  Relay roles need a **key** login (`from_fingerprint` is a key fingerprint);
  password logins can still use the relay server as an ordinary host.
- **Peer table.** Keyed by fingerprint. `ReverseRegister` is checked against the
  connection's own authenticated key (`public_key` must hash to it) and its
  self-signed record (`buildPeerRecordTranscript` / `signPeerRecord`) is verified
  here, not trusted; `ReversePeers` forwards the signed fields so operators verify
  them again themselves. The record `seq` must increase per fingerprint -- and is
  remembered across reconnects (the last 4096 fingerprints), so an old record
  cannot regress a peer. Failures answer an `Error` (the stock client surfaces it
  through `onError`); there is no acknowledgement of success on the wire, so poll
  `listPeers()` (or `server.peerFingerprints()`) if you need to know it landed.
- **Bridge.** `ReverseConnect` is forwarded to the peer with `from_fingerprint`
  (and `username`) set from the operator's authenticated login, whatever the
  client wrote; the peer's `ReverseAccept`/`Reject` goes back, attributed to the
  peer that sent it, and an accept pairs the two connections. From then on every
  spec-`forwardable` message from either end is wrapped as `RelayForward {
  from_fingerprint, inner }` with `from_fingerprint` the sender's authenticated
  key. A `RelayForward` a client writes itself is unwrapped, its inner type
  checked against the allowlist (a non-forwardable or undecodable inner is
  dropped, logged), and re-wrapped with the real sender; traffic from a connection
  that is not bridged is never forwarded.
- **One operator per peer at a time, unless you raise it.** The default: a
  second `ReverseConnect` to a peer that already has an operator (or a request
  awaiting its answer) is rejected with `ReverseReject.reason` `busy: this peer
  already has an operator ...` (exported as `BUSY_PEER` from
  `src/server/relay.mjs`), and an operator that already has a bridge or a
  request in flight is rejected with `busy: you already have a bridge ...`
  (`BUSY_OPERATOR`); a request the peer does not answer within
  `connectTimeoutMs` (default 8 s) is `peer did not respond`. A bridge lasts as
  long as both connections: when either ends, the relay closes the other, so
  nothing an operator started outlives it (the reverse host kills its
  processes). `createReverseHost` redials with backoff by default
  (`reconnect: false` to turn it off), so it is registered again for the next
  operator.
- **Several operators per peer (opt-in on both ends).** Set
  `relay: { maxOperatorsPerPeer: n }` on the relay and
  `createReverseHost({ maxOperators: n })` on the peer. Three things make it
  work, all optional on the wire so nothing older breaks: a peer states
  `relay-multi-operator` in `ReverseAccept.features`; it addresses each message
  to one operator with `RelayForward.to_fingerprint` (the relay routes it there
  and re-wraps it with the peer as sender -- the field is never delivered, and
  a forward addressed to nobody it serves is dropped, as is an unaddressed one
  while two or more are bridged; with exactly one operator an unaddressed reply
  still goes to it); and when one operator leaves the relay sends the peer a
  `ReverseClose { target_fingerprint }` and keeps the peer registered, instead
  of closing it. Each operator is accepted on its own identity (`accept` runs
  per operator) and gets its own connection state on the host -- channels,
  processes, files -- so when one leaves only its work is cleaned up. The relay
  advertises `relay-multi-operator` in its `ServerHello` when it is configured
  for several, and a host only claims it then, so a host with `maxOperators` on
  an older or default relay serves one operator exactly as before. A peer that
  never stated the feature stays held to one operator (and is closed when its
  operator leaves) even on a multi-operator relay; a peer answers one
  `ReverseConnect` at a time (a concurrent one is told `busy: ... retry in a
  moment`), since a `ReverseAccept` does not name its operator; and at the cap
  the reason is `busy: this peer already has its maximum of n operators`
  (`busyPeerFull(n)`). The **Rust relay is still one operator per peer**: it
  never sends `ReverseClose` and rejects the second operator; the new spec
  fields are regenerated into the Rust types and ignored there. Tracked for the
  Rust relay in #93.
- **On the peer**, the bridged operator is served by the same connection code as
  a direct client, over an in-memory message pipe instead of a socket. Nothing a
  client opens can cross the relay but control messages, so exec sessions are
  `data_mode: 'virtual'` there (stdin and output ride `SessionData`; there is no
  stdin EOF).
- **End-to-end encryption through the bridge.** `KeyExchange` and `EncryptedFrame`
  are on the spec's `forwardable` list, so an operator and a peer can run
  `initiateE2E()` / `enableE2E()` with each other through the relay: it carries
  the CBOR of each as opaque bytes and holds no key, so it sees only public
  values and ciphertext (`test/server-relay-bridge.test.mjs` and
  `test/reverse-host-e2e.test.mjs` check the relay never holds the plaintext).
  **`createReverseHost` answers it too** (`e2e` option, on by default; `false`
  turns it off): for a session the host has opened (the id is the one in
  `OpenOk`), an operator's `KeyExchange` is answered -- X25519, or hybrid
  X25519+ML-KEM-768 when asked and available -- and from then on that session's
  output is sealed into `EncryptedFrame`s (AAD = the session id, strict
  counters, the `responder` role tag) and its input is opened from them.
  Plaintext `SessionData` input for an encrypted session is ignored, so a relay
  cannot inject stdin around the encryption, and a replayed, tampered or
  spliced frame is dropped without consuming a counter. The host advertises
  `e2e` (and `e2e-sign`) in `ReverseAccept.features`. Start E2E before the
  session produces output you need confidential: output sent before the key
  exists is plaintext, and a frame that reaches the operator before it has
  called `enableE2E()` is dropped (open the session with a command that waits
  for input, or use a shell and let the first prompt precede the exchange).
  This is virtual-mode E2E (`EncryptedFrame`), so it is offered over a relay
  bridge, not on direct connections (`createWshServer`).
  **`KeyExchange` is unauthenticated by itself**, which protects against a
  relay that only observes; to defeat one that substitutes keys the host
  **signs its reply** with its identity key (Ed25519 over the label, session
  id, algorithm and both ephemeral keys; the optional `KeyExchange.signature`),
  and the operator checks it: `client.initiateE2E(sessionId, algorithm,
  timeout, { verifyPeer: hostPublicKey })` -- the host's raw key, e.g. the
  `public_key` of the record `listPeers()` verified -- rejects with
  `code: 'E2E_PEER_UNAUTHENTICATED'` on a missing or wrong signature, and
  resolves `peerAuthenticated: true` otherwise. Without `verifyPeer` nothing is
  checked, as before. Signing is `e2e: { sign: 'auto' }` by default: the host
  signs when the relay's `ServerHello` carries `e2e-sign` (this package's relay
  does) because a relay built before the field existed -- notably Rust before
  the release that regenerates it -- drops a connection that sends one;
  `sign: true` forces it, `false` never. Key exchange from a connection that
  is not bridged is never carried.
- **Feature gates follow the host behind the bridge.** The host's own features
  (`file-write`, `file-rename`, `mcp-call-id`) are stated in the optional
  `ReverseAccept.features`; the relay forwards the list (bounded: at most 64
  strings of 128 characters, otherwise it is dropped) and, once
  `reverseConnect()` resolves, `client.hasFeature()` / `client.features` answer
  from it instead of the relay's `ServerHello`. `client.bridgedFeatures` is that
  list (`null` before a bridge, or when the peer did not say, in which case the
  gates fall back to `client.serverFeatures`, the relay's, as before).
  `createReverseHost` always states its features (`reportFeatures: false` leaves
  them out). A **Rust `wsh-server` / `wsh` older than `rust-v0.3.0` rejects a
  `ReverseAccept` that carries `features`** (the message is `deny_unknown_fields`
  there): against such a relay or operator, set `reportFeatures: false` on the
  host (and use `ReverseAccept` without the field in your own peers).

#### Operator proof and sealed bridges (#117)

Out of the box the relay tells the host who the operator is (`from_fingerprint`,
set from the operator's login at the relay) and the host's `accept` trusts it:
fine for a relay you run, not for a shared one. Two opt-ins close that, and both
are negotiated by feature strings so every released peer keeps working
(the Rust relay never lists `operator-proof`, so the operator simply does not
offer it there):

```js
// host: do not take the operator's identity from the relay.
createReverseHost({ url, username, keyPair, exec: true,
  requireOperatorProof: true,
  accept: ({ fingerprint, username, proven, publicKey }) => fingerprint === aliceFingerprint });
// operator: prove yourself, and seal the bridge (nothing naming a command is sent before the key exists).
await client.reverseConnect(hostFingerprint, 10_000, { sealed: true, requirePeerProof: true });
```

1. **Operator proof.** After `ReverseConnect` the host sends a signed
   `ReverseChallenge` (its key, the operator fingerprint it saw, a nonce it chose and a
   session id); the operator checks the host's signature, that the key is the host it asked for and that
   the host saw the operator's *own* fingerprint (so a relay that rewrote `from_fingerprint` shows
   up here), and answers with a `ReverseProof`: an Ed25519 signature over the host's key, its own key, the
   username it claims, and the host's nonce and session id. The host verifies it **before `accept` runs**, takes
   the identity from the proof and refuses when it differs from what the relay asserted. `accept` receives
   `{ fingerprint, username, proven, publicKey }`; by default the proof is requested whenever the relay
   and operator can do it and merely *reported* (`proven`).
2. **Sealed bridge.** A proof is a point in time, and a relay can stamp any
   `from_fingerprint` on a plain message afterwards (an injected `Open`), so a host with
   `requireOperatorProof` also requires the bridge to be sealed: the operator opens it with a
   `KeyExchange` that **both** sides sign (the operator's half covers the session id, algorithm, its
   ephemeral key and the host's identity; the host's reply covers both ephemeral keys), hybrid
   X25519+ML-KEM-768 by default, and from then on every message that would cross the relay (`Open`, `OpenOk`,
   `SessionData`, `FileOp`, `McpCall` ...) travels as an `EncryptedFrame` on channel 0 with a strict counter.
   The host acts on nothing else. The only plaintext before the key exists is the key exchange itself (ephemeral
   public keys, signatures); before this change `Open` -- the command, the environment, the working size --
   and `OpenOk` with its resume token crossed the relay in the clear until a per-session `initiateE2E`.

What a relay can and cannot do, with and without these (a relay always sees who connects to whom, when, and how
many bytes):

| The relay can ... | Plain bridge (default) | + operator proof | + `requireOperatorProof` (sealed) |
|---|---|---|---|
| read commands, output, files, MCP calls | yes, until a per-session `initiateE2E` | yes | **no** (ciphertext; metadata and sizes only) |
| make the host think an operator it chose is connecting | yes (it stamps `from_fingerprint`) | **no**: the host verifies the operator's own signature before `accept` | no |
| replay an old operator's login to the host | n/a | **no**: the nonce is the host's, single use, signed over the host's key and the session | no |
| swap the operator's key or the host's ephemeral key | n/a | no (signature does not verify) | no (both halves are signed) |
| inject an `Open` / `SessionData` stamped as the operator | **yes** | **yes** (a proof is a point in time) | **no** (plain messages are dropped) |
| replay or reorder a sealed frame | n/a | n/a | **no** (strict counter and role tag) |
| drop, delay or truncate traffic, or end the bridge | yes | yes | yes (a denial of service is always open to a relay) |
| tell the host the operator is *absent* when it is present (`ReverseClose`) | yes | yes | yes |
| learn the operator's and host's keys, usernames, and the sizes and timing of traffic | yes | yes | yes |

Not covered: an operator or host that skips the checks (the options are opt-in on both
sides; a host that does not require proof is exactly as exposed as before), the Rust `wsh-server` relay and
`wsh` client (they neither carry nor send these messages), and a compromised *operator* key (it proves the key, not the
person). A relay can still refuse service by dropping the challenge.

#### A pipe relay (`@johnhenry/wsh/pipe-relay`, #118)

When you do not want the relay to be a party at all, use a pipe: the host dials the relay, the operator dials the
relay, the relay matches them by an unguessable rendezvous id and copies bytes. **There is no relay-asserted identity**:
the host runs the ordinary handshake and verifies the operator's own signature (`authorize`, `authorizedKeys`,
channel binding, ...) exactly as on a direct connection, and the operator can pin the host key.

```js
import { createPipeRelay, newRendezvousId, pipeUrl } from '@johnhenry/wsh/pipe-relay';
const relay = createPipeRelay({ idleTimeoutMs: 300_000, maxWaiting: 1024 });
const { port } = await relay.listen({ port: 8443 });          // or relay.accept(socket, { id, role }) from your own HTTP server

const id = newRendezvousId();                                  // 128 bits; hand it to both sides out of band
// host (behind NAT): dial out, wait for the socket to open, serve it like any accepted connection
const ws = new WebSocket(pipeUrl('wss://relay.example', id, 'host'));
await new Promise((r) => ws.addEventListener('open', r, { once: true }));
await server.accept(ws);                                       // createWshServer / createMemoryHost
// operator: the stock client, any URL form
await client.connect(pipeUrl('wss://relay.example', id), { username, keyPair, expectHostKey });
```

The module imports nothing that can execute code or read files (a test walks its module graph); it does not parse wsh.
Bounds, all with defaults: `maxWaiting`, `rendezvousTimeoutMs`, `idleTimeoutMs`, `maxLifetimeMs`, `maxBytes`,
`maxMessageBytes`, `earlyBytes`, `highWaterBytes` (a receiver that is not draining pauses the sender; a socket that
cannot pause is closed). **Trust difference:** relay mode has the relay vouch for the operator; a pipe relay vouches
for nothing, and the rendezvous id is the only thing standing between the host's socket and whoever dials first --
an impostor that reaches the id first is still a stranger to the operator, who must pin the host key
(`expectHostKey`) to notice; and the host still authenticates every operator. A pipe relay terminates the TLS of each leg, so what it copies -- the wsh
handshake and the session traffic -- is readable by it unless the two ends seal it themselves
(per-session `initiateE2E`); it cannot forge the operator's signature or the host's. It can drop, delay or
cut a connection, and it sees who dials which id and how much they send.

*CLI side (not built here).* The Rust `wsh` client always dials `wss://<host>/` (#136), so it cannot dial
`/r/<id>` yet. It needs either `wsh --via wss://relay/r/<id> user@host`, or to keep the URL path and query it is
given; the JS client already does. The host side is any process that can open a WebSocket to `pipeUrl(..., 'host')`
and hand it to `accept`.

### Sessions: attach / resume / detach

By default a pty/exec session dies with the connection that opened it. Pass
`sessions` and it outlives it, so a dropped socket (a flaky link, a closed
tab) can be picked up again:

```js
createWshServer({
  auth, exec: true, pty: { spawn: nodePty.spawn },
  sessions: {
    detachTtlMs: 300_000,   // how long a session nobody is attached to keeps running (0 = kill at once)
    maxDetached: 16,        // unattended sessions kept at once; the longest-detached is killed beyond that
    ringBytes: 1 << 20,     // output history kept per session: what a resume can replay
    // sessionSecret: process.env.WSH_SESSION_SECRET,  // fixes the token key (default: random per process)
  },
});
```

```js
// original connection
const s = await client.openSession({ type: 'pty' });
s.onData = (d) => term.write(d);            // s.seq counts the output bytes received so far
const { sessionId, resumeToken } = s;       // keep these
const lastSeq = s.seq;                      // ... the socket drops ...

// fresh connection, same key
const { session } = await client2.resumeSession(sessionId, resumeToken, { lastSeq });
session.onData = (d) => term.write(d);      // only the bytes after lastSeq, then live output
await session.write('ls\n');                // and it is the same process
```

- **`seq` is the cumulative count of output bytes** the host has produced for
  a session (stream data or `SessionData` alike). The client counts what it
  received -- `WshSession.seq` -- so no per-frame field exists, and
  `Resume.last_seq` is exactly that number. The host keeps the newest
  `ringBytes` of output and replays `ring[last_seq - ringStart ..]`. A
  `last_seq` older than the ring still holds is refused with an
  `output gap` error naming where the history starts (fall back to
  `attachSession()` for the retained tail); one newer than the session has
  produced is refused too. While nobody is attached the process keeps running
  and keeps filling the ring (it is never paused), so a chatty process loses its
  oldest output rather than blocking.
- **Token:** `HMAC-SHA256(secret, session_id || expiry)` in the spec's
  40-byte token format, minted at open, returned as `OpenOk.token` and checked
  in constant time. **`Resume` needs the token AND ownership** (the same key, or
  for a password login the same username) -- it is the credentialed connection
  coming back. **`Attach` accepts the token OR ownership**, so the owner can
  re-attach with nothing but the session id, and a token holder can join as a
  guest. Refusals do not say whether the session exists.
- **What arrives:** the Presence reply names a new channel (`channel_id`) and the
  `seq` of its first byte; the replay and live output follow as `SessionData` on
  it. That channel is always message-backed, even for an `exec` session that was
  opened on a data stream -- neither stock client opens a stream for attach/resume
  -- so `resumeSession()`/`attachSession()` return the Presence with a
  non-enumerable `session` (a `WshSession`) to read and write it. A client that
  ignores that can read the same frames with `addControlListener()`.
- **Several connections** may attach to one session (up to 16): output fans out
  to all of them, `attachSession(id, { readOnly: true })` attaches a viewer whose
  input is dropped, and every change in who is attached is broadcast as `Presence`
  (the roster, without channel ids).
- **Ending vs leaving:** `Close` on a channel (which `session.close()` and a
  graceful `client.disconnect()` send) *ends* the session when its owner sends it,
  and merely leaves it for anyone else. To walk away from a session and keep it
  running, `client.detach(sessionId)` first; losing the connection also detaches.
  `client.listRemoteSessions()` lists the sessions your key owns, attached or not.
- Exit: when the process ends, everyone attached gets `Exit` + `Close`; the
  record then lingers for `detachTtlMs` so a late resume still collects the tail
  and the exit code.
- Not built: ACL grants (`SessionGrant`/`SessionRevoke`) and `ControlChanged` --
  only the owner re-attaches as a controller; everyone else needs the token.
  Sessions are in-memory: a server restart ends them all.

### Cancelling transfers and tool calls

```js
const ac = new AbortController();
const p = client.upload(bytes, 'big.bin', { signal: ac.signal });
ac.abort();                       // p rejects with an AbortError and the file channel is closed
await client.download('big.bin', { signal });
await client.callTool('search', { q: 'x' }, { timeout: 30_000, signal });
const pty = client.getSession(client.listSessions()[0].channelId); // live session: write() / close()
```

An aborted upload writes nothing (the server writes the file only when the last chunk arrives). An aborted `callTool`
also sends `McpCancel` to a host advertising `mcp-cancel`, so the tool handler's `ctx.signal` fires. The Rust `wsh-server`
advertises it from `rust-v0.6.0`: it drops the call's task and kills the tool's process group, and offers CLI tools
from `[[mcp.tools]]` entries in its `config.toml`.

### MCP tools

`createWshServer({ mcp })` answers `McpDiscover` and `McpCall`, so the stock
`client.discoverTools()` / `client.callTool()` and `WshMcpBridge` work against
it. Off unless you pass it.

```js
const server = createWshServer({
  auth,
  mcp: {
    tools: [{
      name: 'read_note',
      description: 'Read a note by id',
      inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'], additionalProperties: false },
      call: async ({ id }, { user, signal }) => ({ success: true, output: await readNote(id, { signal }) }),
    }],
    authorize: (user, tool) => tool.name !== 'admin_only' || user === 'root',   // optional
    // client: mcpSdkClient,   // optional: proxy an @modelcontextprotocol/sdk Client's tools too
    // maxConcurrent: 8, timeoutMs: 30_000,
  },
});
```

- **Tool shape:** `tools` is an array of `{ name, description, inputSchema,
  call(args, { user, fingerprint, signal }) }` or a `{ name: { ... } }` map.
  `inputSchema` is advertised to clients as `parameters` (the `McpToolSpec`
  field).
- **Arguments are untrusted.** They are validated against `inputSchema` before
  `call()` runs; invalid arguments never reach the tool. The package has no
  runtime dependencies, so the validator covers the keywords tool schemas use
  (`type`, `enum`, `const`, `properties`, `required`, `additionalProperties`,
  `items`, length/range/`pattern`/`multipleOf` bounds, `allOf`/`anyOf`/`oneOf`/
  `not`, local `$ref`); a schema using any other keyword (`if`,
  `patternProperties`, ...) is **refused when the server is created** rather than
  silently enforced less strictly. Only tools you list are reachable.
- **Results:** whatever `call()` returns is `McpResult.result` verbatim (the
  stock `WshMcpBridge` normalizes the `{ success, output, error }` shape, and
  wraps anything else as `{ success: true, output }`). A tool that throws, an
  unknown tool, invalid arguments, a timeout or the concurrency cap all answer
  `{ success: false, error }` -- the error text is the thrown `message`, so
  throw messages you are happy for the caller to read.
- **Correlation:** every `McpResult` echoes the call's `call_id`, and the
  server advertises `mcp-call-id` (when `mcp` is configured), so concurrent
  calls from one client get their own results, and a slow tool does not hold up
  the calls behind it.
- **Limits:** `maxConcurrent` in-flight calls per connection (default 8) and a
  `timeoutMs` per call (default 30000). On timeout or disconnect the tool's
  `signal` aborts; a tool that ignores it keeps running but its reply is dropped.
- **Access:** discovery and calls are answered after authentication only.
  `authorize(user, tool, { username, fingerprint })` filters both, and a tool
  hidden from a caller is indistinguishable from one that does not exist.
- **Proxying:** `client` takes anything with `listTools()` / `callTool()` (an
  `@modelcontextprotocol/sdk` `Client`; this package does not import the SDK).
  Its tools are re-listed on every discovery, validated against their own
  `inputSchema`s here, and `isError` results become `{ success: false, error }`,
  else the result is `structuredContent` or the `content` array. A proxied tool
  whose schema uses an unsupported keyword is not exposed.
- Without `mcp`, `McpDiscover` answers an empty list and `McpCall` an
  `{ success: false, error: 'mcp is not enabled on this server' }` result.

### Host key (fingerprint / TOFU)

Give the server an identity and the stock client can pin it:

```js
// server
const server = createWshServer({ auth, hostKey: { file: '/etc/wsh/host_key' } });
await server.listen();
server.hostKey();   // { fingerprint, publicKey, openssh } -- publish this out of band

// client
import { WshClient, WshKnownHosts, HostKeyError } from '@johnhenry/wsh';
const client = new WshClient();
await client.connect(url, { username, keyPair, expectHostKey: fingerprint });   // pin; refuses on mismatch
// or trust-on-first-use, remembered in a store:
await client.connect(url, { username, keyPair, knownHosts: new WshKnownHosts(), trustOnFirstUse: true });
client.hostKey;  // { fingerprint, publicKey, openssh, status: 'pinned' | 'known' | 'unknown' | 'unpinned' }
client.onHostKey = (hk) => confirm(`Trust ${hk.fingerprint}?`);   // or per call: connect(..., { onHostKey })
```

- `hostKey` is `{ file }` (a PKCS#8 PEM, created mode 0600 on first start --
  use this), a `CryptoKeyPair`, or `true` (a fresh key every start: every TOFU
  client will see "changed" after a restart; tests and demos only).
- `expectHostKey` takes a hex fingerprint (`sha256:` prefix fine), raw 32-byte
  key, or an `ssh-ed25519 AAAA...` line. With `knownHosts`, a **changed** key is
  always refused (and never overwrites the pin); an **unseen** host is refused
  unless `trustOnFirstUse` is set or `onHostKey` accepts it. Either option also
  refuses a host that presents no key at all. Refusals are `HostKeyError` with
  a `code` (`HOST_KEY_MISSING | _INVALID | _MISMATCH | _UNKNOWN | _REJECTED`),
  thrown **before any credential -- signature or password -- is sent**.
- `WshClient.exec()` and `connectReverse()` accept the same options.
- `WshKnownHosts` defaults to `localStorage`, which in Node is not a persistent file store: for a real TOFU file pass `new WshKnownHosts({ storage })` with a `getItem`/`setItem`/`removeItem` object you back with a file.
- Wire shape: the spec's `ServerHello.host_fingerprint` is populated, and
  because a bare fingerprint proves nothing (anyone can repeat it) the key and
  a signature ride in `features` strings: the client sends `host-key-nonce:<hex>`
  in `Hello`; the server answers `host-key:<hex>` and `host-key-sig:<hex>`
  (Ed25519 over a tag, the session id, the client's nonce and the username).
  The fresh nonce makes the proof unreplayable. Hosts that don't know these
  strings ignore them (the Rust `wsh-server` advertises no key, so a pin
  against it is refused with `HOST_KEY_MISSING`, never silently skipped).
- **What it does not give you:** the proof authenticates the ServerHello, not
  the byte stream. Over plain `ws://` an active attacker can relay a genuine
  ServerHello and then read or alter the rest. Pinning keeps you from talking
  to the wrong host; confidentiality still needs `wss://` or a link you trust.

### Channel binding (tie the login to the connection)

A host key proves who the host is; it does not stop an intermediary from
passing a genuine challenge through to the host and getting your login
signature back. With binding, the signature also covers what the two ends of
*this* connection share, so a relayed signature is worthless to the host:

```js
// host: accept a key login only when it is bound (requires hostKey for `host`; wss served by this process for `tls-exporter`)
createWshServer({ auth, hostKey: { file }, requireChannelBinding: true });   // or ['host', 'tls-exporter']
// client: refuse to sign a login that cannot be bound
await client.connect(url, { username, keyPair, requireChannelBinding: true });
client.channelBinding;   // ['host'] -- which kinds this login's signature covered
```

| Kind | Bound to | Who can supply it |
|---|---|---|
| `host` | the Ed25519 host key that proved possession in `ServerHello` | a host with `hostKey`; any client that checked the proof (so a relay presenting its own key binds to *its* key) |
| `cert-hash` | the SHA-256 of the pinned WebTransport certificate | a `selfSigned` WebTransport host; a client with exactly one `serverCertificateHashes` entry |
| `tls-exporter` | 32 bytes of TLS keying material (RFC 5705/8446, label `EXPORTER-wsh-channel-binding`) | Node on both ends over `wss://` served by the process itself (the client must use the `ws` package, e.g. `new WebSocketTransport({ WebSocket })`; Node's global `WebSocket` and every browser expose no exporter) |

It is negotiated with feature strings (`channel-binding:<kind>`,
`channel-binding-required`), so released clients and hosts keep working: a
host that does not require binding still accepts an unbound login, and a
client binds whatever the host offers. A host that requires it refuses an
unbound signature with a reason. **What it does not do:** it protects only
what you require. An intermediary that strips the host's offer gets an unbound
signature from a client that did not set `requireChannelBinding`, and a host
that does not require binding accepts it -- set the option on whichever side
you control (a host protects every client; a client protects itself).
`tls-exporter` fails behind a TLS-terminating proxy by design. Password logins
are not bound (nothing is signed). The Rust `wsh-server` and `wsh` CLI do not
offer or compute a binding yet, so against them a client with
`requireChannelBinding` refuses to log in.

### Password auth

```js
createWshServer({
  auth: {
    password: async (username, password) => verifyAgainstYourHashes(username, password),
    // authorizedKeys / authorize may be given too: both methods are then served.
    rateLimit: { maxFailures: 5, windowMs: 60_000, lockoutMs: 60_000, failureDelayMs: 250 },
  },
});
await client.connect(url, { username, password });
```

The wire already has it (`Hello.auth_method: 'password'` then `Auth{ method:
'password', password }`, no challenge), so no extension is involved -- and
that is also its limit: the password travels as plain text inside the
connection, so serve password logins over `wss://` (TLS-terminating proxy)
or a link you trust, and pin the host key so it is only ever sent to the right
host. Use a constant-time comparison against stored hashes in the callback,
never `===` on plaintext. A host with only `password` refuses key logins and
vice versa; with neither configured every connection is refused.

Failures are throttled per peer address (override with `rateLimit.key`, e.g.
read `x-forwarded-for` from `headers` behind a proxy): each connection gets one
guess, a failed one is answered after `failureDelayMs`, and after
`maxFailures` in `windowMs` the caller is locked out for `lockoutMs` -- the
callback is not even consulted during lockout, so the right password does not
get through either. The counter is in-process memory and per server.

### Files: write and rename

`client.fileWrite(path, data, offset?)` and `client.fileRename(from, to)` work
against the server's `fs` (earlier versions of the client sent neither the
bytes nor the new path). Without `offset`, `fileWrite` replaces the file
(creating it); with one, it writes in place at that byte offset without
truncating. `fileRename` refuses to overwrite an existing destination, to move
a directory into itself, or to touch the root. Both honour `readOnly` and
`maxFileBytes`, and a failure comes back as `success: false` with an
`error_message`.

`FileOp` has no field for the bytes or the destination, so both use
spec-conformant frames only: the `FileOp` is followed by `FileChunk` frame(s) on
the same channel id (for `rename`, one chunk holding the UTF-8 destination).
The host advertises `file-write` / `file-rename` in `ServerHello`; the client
throws instead of sending to a host without them (the Rust `wsh-server`
refuses these ops).

### Compatibility: announce vs. primer

An exec session's output flows on a second, client-opened stream, and a QMux
stream is invisible on the wire until its first byte. Two mechanisms exist for
the host to find it:

| Client | Host | What happens |
|---|---|---|
| Current stock client | `@johnhenry/wsh/server` (advertises `stream-announce`) | The client's transport announces the stream with an empty STREAM frame. **No primer is written.** |
| Current stock client | Host without `stream-announce` (e.g. the Rust `wsh-server`, older vendored hosts) | The client writes a one-byte primer (`0x00`) on the new stream so the host sees it; that host strips it. `primer: false` disables this (then such a host never binds the stream and the output is lost). |
| A client that primes anyway (older stock client, `primer` forced, other implementations) | `@johnhenry/wsh/server` | **The leading `0x00` is dropped:** if the first data on an exec stream is exactly one `0x00` byte it is discarded, never forwarded to the process's stdin. Only that first chunk is inspected; a later `0x00`, or a first chunk that is longer than one byte, is delivered untouched. The cost: a client whose genuine first stdin chunk is a lone NUL loses it. |
| A client that neither announces nor primes (a third-party QMux client; the stock client always does one or the other) | `@johnhenry/wsh/server` | The host waits `bindTimeoutMs` (default 3000) for the stream, then drops the output and logs it. This cannot be fixed host-side: nothing about the stream has been sent, so there is nothing to bind. Such a client must send `QMuxStream.announce()` (an empty STREAM frame) or any first write -- a zero-length `write()` now does the same. |

## RPC channels (object mode)

An `rpc` channel is an ordinary QMux stream whose payload is a sequence of
**objects**, not bytes -- wsh's counterpart of an SSH *subsystem*: SSH channels
are byte streams, SFTP is a typed, id-correlated protocol layered inside one.
Each message is one CBOR data item (a [CBOR sequence](https://www.rfc-editor.org/rfc/rfc8742),
self-delimiting, no length prefix) shaped as JSON-RPC 2.0, so MCP maps 1:1 and
binary values are native byte strings (`Uint8Array`). Stream-announce,
backpressure and close/reset apply unchanged; the control plane, the Rust
codegen and exec/pty byte streams do not change.

```js
// client
const rpc = await client.openRpc('mcp', { timeoutMs: 30_000 });   // sugar over openSession({ type: 'rpc', protocol })
const { tools } = await rpc.request('tools/list', {});            // rejects with RpcError
rpc.notify('notifications/initialized');
rpc.onRequest('sampling/createMessage', async (params, ctx) => ({ /* server -> client request */ }));
const call = rpc.request('read', { path: 'big.bin' }, { onProgress: (chunk) => {} });   // $/progress chunks
call.cancel();                                                    // $/cancel; rejects -32001 now, late answer dropped
rpc.onProgress(call.id, (chunk) => {});                           // or attach to a request already in flight
await rpc.close();

// server
import { createWshServer, mcpServerAdapter } from '@johnhenry/wsh/server';
createWshServer({
  auth, fs: { root: '/srv/files' },
  rpc: {
    'wsh-host': true,                       // host.info, host.ping
    'wsh-fs': true,                         // the server's `fs`; or { root, readOnly, maxFileBytes }
    mcp: mcpServerAdapter(mcpServer),       // any @modelcontextprotocol/sdk Server (or a factory for one per channel)
    custom: (channel, ctx) => {             // anything else: a function run per opened channel
      channel.onRequest('echo', (params, { signal, progress }) => params);
    },
  },
});
```

**Negotiation.** The host advertises `rpc`, one `rpc-protocol:<name>` per
protocol and `rpc-max-message:<bytes>` (default 1 MiB) in `ServerHello.features`.
`openRpc()` / `openSession({ type: 'rpc', protocol })` refuse an unadvertised
`rpc` or protocol with an `RpcError` (`code` -32000, `reason: 'UNSUPPORTED_PROTOCOL'`)
**before sending any bytes**. `Open.command` carries the protocol name (the
`Open` message has no other free field; `kind` is `'rpc'`).

**Semantics.** `id` is unique per direction per channel and both sides may
request. Responses are matched by `id` only (the class of bug behind #72).
`$/cancel { id }` asks the callee to stop: it answers `-32001` at once, its
`ctx.signal` aborts, and the caller drops any late result. `$/progress
{ id, chunk }` notifications may precede the final response (file reads, logs).
Closing the stream rejects every pending request with `-32001` / `reason:
'channel-closed'`. Error codes: JSON-RPC's `-32700..-32603`, plus `-32000`
unsupported protocol, `-32001` cancelled / timed out / closed, `-32002` too many
requests in flight (`rpcMaxInflight`, default 64), `-32003` unauthorized.
A message over the negotiated maximum is refused locally when sending and
closes the channel when received.

**Built-in protocols**

| Protocol | Methods |
|---|---|
| `wsh-host` | `host.info` -> `{ version, protocol, features (this connection's ServerHello), hostFingerprint, user, rpc }`; `host.ping` -> `{ time }` |
| `wsh-fs` | `stat`, `list`, `mkdir`, `remove`, `rename { path, newPath }`, `write { path, data, offset? }`, `upload { path, data, offset? }` (offset omitted/0 creates or truncates, later offsets continue in place: chunk big files), `read { path, offset?, length? }` and `download { path }` (the bytes arrive as `$/progress` chunks of at most 64 KiB; the result is `{ size, offset, length, eof }`). Same confinement as `fs`: no traversal or symlink escapes, `readOnly`, `maxFileBytes`; policy refusals are `-32003`. |
| `mcp` | The MCP JSON-RPC surface verbatim; see below |

When a host advertises `rpc-protocol:wsh-fs`, `fileStat` / `fileList` / `fileRead` /
`fileWrite` / `fileRename` / `fileMkdir` / `fileRemove` use it (results keep the
`FileResult` shape; `client.preferRpcFiles = false` opts out). The control-plane
`FileOp`/`FileResult` path stays for hosts that do not advertise it.

**MCP.** `mcpServerAdapter(server)` implements the official SDK's `Transport`
interface over the channel, so any `Server` can be exposed (pass a factory
`(ctx) => new Server(...)` for one per channel; an instance serves one channel
at a time). On the other end, `mcpClientTransport(channel)` is a `Transport` for
the SDK's `Client`:

```js
const channel = await client.openRpc('mcp');
const mcp = new Client({ name: 'me', version: '1' }, { capabilities: {} });
await mcp.connect(mcpClientTransport(channel));
await mcp.callTool({ name: 'echo', arguments: { text: 'hi' } });
```

MCP is already JSON-RPC, so the adapter is a pass-through: request ids,
results, errors and notifications (including `notifications/progress`) are
forwarded verbatim. The one translation is cancellation: an MCP client abort
(`notifications/cancelled`) becomes `$/cancel` on the wire, and an incoming
`$/cancel` is delivered to the SDK as `notifications/cancelled`, so the tool
handler's `signal` fires. The SDK is **not** imported by this package (the
transport is structural); `@modelcontextprotocol/sdk` is an optional peer for
whoever supplies the `Server`/`Client`, and the package root stays
dependency-free and browser-safe.

**Compatibility.** Purely additive. Old clients never open `rpc` sessions; an old
host does not advertise `rpc`, so a new client fails fast with
`UNSUPPORTED_PROTOCOL` instead of waiting on an `OpenFail`. `@johnhenry/wsh/server`
and the Rust `wsh-server` (see below) serve `rpc` today. Not goals: a
replacement for byte streams (exec/pty are unchanged), a new transport (`rpc`
rides WebSocket/QMux and WebTransport streams), or an auth change -- an `rpc`
session is opened on an authenticated connection and per-method authorization is
the handler's job (`-32003`; `ctx.user` / `ctx.fingerprint` identify the caller).
Handlers run per channel, so register methods synchronously (or before the
returned promise settles: inbound messages are held until it does).

**The Rust `wsh-server`** (since `rust-v0.4.0`) serves `wsh-host` and `wsh-fs`
exactly as the JS server does -- same features, methods, parameters, results,
error codes and messages, same CBOR-sequence decoder and size bound, same
`$/cancel` / `$/progress` -- over a WebSocket (QMux) connection. It does not
serve `mcp` (hosting an MCP server is an embedding concern) and does not offer
`rpc` on the native WebTransport listener, whose single control stream has no
client-opened data streams to carry a channel. `wsh-host` is on by default;
`wsh-fs` is **off until you give it a root** (file access is opt-in), and is
confined to it the way the JS `fs` option is. In `~/.wsh/config.toml`:

```toml
[rpc]
enabled = true            # default; false turns rpc off entirely
max_message_bytes = 1048576   # advertised as rpc-max-message:<n>; at least 256
max_inflight = 64         # concurrent requests per channel before -32002
fs_root = "/srv/files"    # unset (the default): wsh-fs is not offered
fs_read_only = false
fs_max_file_bytes = 67108864
```

Key options apply as they do to other channels: a key restricted to a forced
command opens no rpc channel, and `wsh-fs` needs the `file-transfer` scope
(`permit-file-transfer` under `restrict`). `host.info` reports the crate version
and `hostFingerprint: null` (the Rust server has no host key). The JS client
needs nothing new: it reads `rpc` from `ServerHello`, and its file helpers prefer
`wsh-fs` automatically once the server offers it.

## Attach and Resume

Opening a PTY/exec session returns a session-scoped credential alongside the channel:

```js
session.sessionId;   // server-assigned session id (undefined for e.g. file channels)
session.resumeToken; // token minted at open time; only the opener receives it

// The original opener, reclaiming its session from a fresh connection,
// replaying only the output it has not yet seen (`session.seq` counts it):
await client.resumeSession(session.sessionId, session.resumeToken, { lastSeq });

// Any other authorized principal attaches without a token -- ownership
// or an ACL grant is enough:
await client.grantSessionAccess(session.sessionId, 'bob');  // by the owner
await otherClient.attachSession(session.sessionId);         // by 'bob'

// Other session-management round trips:
await client.detach(session.sessionId);   // leave it running server-side
await client.listRemoteSessions();        // sessions this key can see
```

`@johnhenry/wsh/server` implements all of it with its [`sessions`
option](#sessions-attach--resume--detach), and so does the Rust `wsh-server`
(since `rust-v0.2.0`): `Resume` replays only the output after `last_seq`
(the position is defined in [spec/wsh-v1.md](spec/wsh-v1.md)), and Attach/Resume
answer with a Presence carrying the new `channel_id` and `seq`, replay and live
output arriving as `SessionData` on it. The Rust host's ring is a fixed 256 KiB
per session and its sessions end with the server process; a session that exits
while no one is attached is kept (for the replay and the exit) until it is
resumed or expires.

## Pinning a Self-Signed Certificate

Both transports normally need a certificate a public certificate authority
signed. On a LAN -- a phone talking to a desktop on `192.168.x.x`, a
browser talking to a device on the same Wi-Fi -- there is no such
certificate to be had, and a plaintext `ws://` from an `https://` page is
blocked as mixed content.

WebTransport is the one place in the web platform with an answer:
`serverCertificateHashes` lets the page pin a specific certificate by
SHA-256 digest, no certificate authority involved.

```js
// The digest can be raw bytes, base64, plain hex, or the colon-separated
// hex `openssl x509 -fingerprint -sha256 -noout -in cert.pem` prints --
// the whole `SHA256 Fingerprint=AB:CD:...` line is accepted as-is.
await client.connect('https://192.168.1.20:4433/wsh', {
  username: 'alice',
  keyPair,
  transport: 'wt',
  webTransport: {
    serverCertificateHashes: [
      'SHA256 Fingerprint=A1:B2:C3:...',
    ],
  },
});
```

`WebTransportTransport` also takes the same options directly, for use with
`connectWithTransport()`:

```js
const transport = new WebTransportTransport({
  serverCertificateHashes: [certDigestBytes],
});
```

A malformed digest throws locally (`RangeError` for the wrong length,
`TypeError` for an unrecognised shape) before any connection is
attempted -- a wrong hash otherwise surfaces only as an opaque
`WebTransportError` from `wt.ready`.

The constraints are the platform's, not wsh's:

- The URL must be `https:`; pinning is HTTP/3 only, with no HTTP/2 fallback.
- The certificate must use an **ECDSA P-256** key and be valid for **at most
  14 days**, so it has to be reissued on a schedule. `serverCertificateHashes`
  takes several digests: pin the current and the next one across a rotation
  (the Node host's `certificateHashes()` publishes both; see
  [Certificate rotation](#certificate-rotation)).
- Connection pooling is disabled for a pinned connection.
- Only `sha-256` is accepted as the algorithm.

The option applies to the WebTransport rung of the transport ladder only.
If the WebTransport attempt fails and the client falls back to WebSocket,
that `wss:` connection is subject to the ordinary certificate-authority
check again -- there is no WebSocket equivalent of certificate pinning.
Pass `transport: 'wt'` if you would rather fail than fall back.

Any other key in `webTransport` is forwarded to the `WebTransport`
constructor verbatim (`congestionControl`, `allowPooling`,
`requireUnreliable`, the `anticipatedConcurrentIncoming*Streams` hints),
so options the platform gains later need no change here.

## API Overview

### Core Classes

| Class | Description |
|-------|-------------|
| `WshClient` | Full lifecycle client: connect, auth, sessions, reverse mode, MCP |
| `WshSession` | Single PTY or exec channel with read/write/resize/signal |
| `WshTransport` | Abstract transport base class |
| `WebTransportTransport` | WebTransport implementation (native streams); takes `serverCertificateHashes` and other `WebTransport` options |
| `WebSocketTransport` | WebSocket implementation (multiplexed virtual streams) |

### Utilities

| Class / Function | Description |
|------------------|-------------|
| `WshKeyStore` | Ed25519 key management via IndexedDB + OPFS encrypted backup |
| `WshFileTransfer` | File upload/download over dedicated streams |
| `WshMcpBridge` | Remote MCP tool discovery and invocation |
| `RpcChannel` / `RpcError` | Typed RPC channel (JSON-RPC 2.0 over a CBOR sequence): `client.openRpc(protocol)`; `RPC_FEATURE`, `rpcProtocolFeature(name)`, `RPC_ERROR`, `CborSequenceDecoder` |
| `mcpClientTransport()` / `mcpServerAdapter()` (`/server`) | MCP SDK `Transport` over an `rpc` channel |
| `SessionRecorder` | Record PTY I/O with timestamps (asciicast-v2-shaped JSON; convert to play in asciinema, see the note under Session recording) |
| `SessionPlayer` | Replay recordings with original timing |
| `generateKeyPair()` | Create Ed25519 key pair via Web Crypto |
| `sign(privateKey, message)` / `verify(publicKey, signature, message)` | Raw Ed25519 sign / verify. This positional order (WebCrypto's) is the one canonical form across wsh, raijin and browsermesh |
| `signChallenge()` | Build transcript + sign for auth handshake |
| `signPeerRecord()` / `verifyPeerRecord()` | Sign / verify reverse-mode peer records |
| `fingerprint()` | SHA-256 hex fingerprint of a public key |
| `podId()` / `fingerprintToPodId()` / `podIdToFingerprint()` | The same SHA-256 as base64url, the BrowserMesh pod ID: `await podId(raw) === await derivePodId(cryptoKey)` (`@johnhenry/browsermesh-primitives`) for the same Ed25519 key, so one key carries both the wsh fingerprint and the mesh identity. The two converters are pure re-encodings between the two forms |
| `parseCertificateHash()` | Decode a certificate digest from hex / base64 / bytes |
| `normalizeWebTransportOptions()` | Build a `WebTransportOptions` dictionary from loose input |

### Protocol

| Export | Description |
|--------|-------------|
| `MSG` | 105 message type constants (hex opcodes) |
| `CHANNEL_KIND` | Channel types: `pty`, `exec`, `meta`, `file`, `tcp`, `udp`, `job` |
| `AUTH_METHOD` | Auth methods: `pubkey`, `password` |
| `cborEncode` / `cborDecode` | CBOR codec (maps, arrays, strings, ints, bytes, bools, null, floats) |
| `frameEncode` / `FrameDecoder` | 4-byte big-endian length-prefixed framing |
| `QMuxConnection` + QMux primitives | QMux stream state machine, error codes, and stream-id helpers for building alternate servers |

## Protocol Specification

The `spec/` directory contains the protocol definition:

- `wsh-v1.yaml` -- machine-readable protocol schema
- `wsh-v1.md` -- human-readable protocol specification
- `codegen.mjs` -- generates `messages.gen.mjs` from the YAML spec

## Rust implementation

`crates/` is a native Rust implementation of the wsh protocol, moved into
this repo from erisera-code/clawser on 2026-09-06 (with history, via `git
subtree`) so it lives next to the JS client whose wire spec it implements
instead of dragging its own toolchain and CI job into an unrelated
browser-app repo. It was previously deleted from clawser by accident
(2026-03-14) and restored (2026-07-05) before this move.

Four crates, workspace-versioned (currently `0.5.0`):

| Crate | Kind | Description |
|-------|------|--------------|
| `wsh-core` | library | Shared protocol types -- CBOR messages (generated, see below), codec, identity, auth, QMux |
| `wsh-client` | library | Native Rust client -- WebTransport/WebSocket transports, sessions, file transfer, E2E |
| `wsh-cli` | binary (`wsh`) | SSH-like CLI: connect, exec, scp-style copy, reverse tunnels, key management |
| `wsh-server` | binary (`wsh-server`) | Server: WebTransport/WebSocket listener, real PTY sessions (`portable-pty`), relay/reverse-connect, WISP bridging |

### Running a command with `wsh`

```sh
wsh alice@host ls -l                          # dials https://host:4422, then wss://host:4422
wsh -t ws -p 8443 alice@host ls -l            # wss:// only, on port 8443
wsh wss://host:8443/rendezvous/ab12 ls -l     # a full URL, dialled exactly as written (path and query kept)
printf 'a\nb\n' | wsh alice@host sort         # stdin is forwarded; its end reaches the command as EOF
wsh --tty alice@host top                      # a terminal for the command: raw keys, resizes forwarded
```

stdout and stderr stay separate where the host offers `exec-pipes`; the exit status is the command's.
SIGINT, SIGTERM and SIGHUP sent to `wsh` are forwarded to the command, and the same signal twice
disconnects. `wsh connect` ends when the remote session does. Diagnostics go to stderr (`-v` for more),
never into the command's stdout. TLS uses the platform trust store, and `SSL_CERT_FILE` points it at another certificate (how a self-signed host is trusted); a plain
`ws://` URL is accepted only for a loopback host.

### Capability matrix: JS SDK vs Rust CLI/client

Two implementations of one protocol will always have *some* asymmetry --
the question wsh #59 asks is whether it is visible and deliberate, or
discovered by accident. This table is that answer, made explicit rather
than left to be found.

| Capability | JS SDK (browser) | Rust CLI/client | Unified via |
|---|---|---|---|
| Directory listing (`list`) | `WshFileTransfer.list()` | `wsh_client::file_transfer::list()`, `wsh ls`, `wsh sftp` | **Wire-unified**: `FileOp`/`FileResult` with the generated `FileEntry` type (wsh #59) -- both languages decode the same shape, including symlink targets |
| Upload/download | `WshClient.upload()`/`.download()` | `file_transfer::upload()`/`download()`, `wsh scp` | **Wire-unified**: `FileChunk` over a `'file'`-kind channel (wsh #13) |
| Remove a remote file | `WshClient.fileRemove()` | `file_transfer::remove()`, `wsh sftp`'s `rm` | **Wire-unified**: `FileOp`/`FileResult` (`op: "remove"`) -- refused today by every `wsh-server` release ("not yet implemented"), the same refusal on both sides |
| Install an authorized key | `WshClient.addAuthorizedKey()` | `wsh_client::WshClient::add_authorized_key()`, `wsh copy-id` | **Wire-unified** (wsh #59): `AuthorizedKeyAdd`/`AuthorizedKeyResult`, replacing a Rust-CLI-only shell command with a message every implementation can send |
| Host identity / TOFU | `WshKnownHosts` (localStorage-backed) | `KnownHosts`/`HostStatus` (`~/.wsh/known_hosts`-backed) | **Record unified, policy is not** (wsh #59): both pin `ServerHello.host_fingerprint`, which `@johnhenry/wsh/server` populates (with a proof of possession, [Host key](#host-key-fingerprint--tofu)) but no Rust `wsh-server` release does yet (see [Security](#security-model)). *When* to trust, prompt, or persist is deliberately left per-implementation -- a browser and a CLI have different UX for "first time seeing this host" |
| Typed RPC channels (`openRpc`, `rpc` sessions; `wsh-host`, `wsh-fs`, `mcp`) | `WshClient.openRpc()`, `RpcChannel` | Rust `wsh-server` (`rust-v0.4.0`+): `wsh-host`, and `wsh-fs` when `[rpc] fs_root` is set; no client yet in `wsh-client` | **No wire change**: `Open { kind: 'rpc', command: <protocol> }` plus `rpc*` `ServerHello` features, negotiated so it fails fast elsewhere; the Rust server serves it on WebSocket/QMux only |
| Exec stdin + EOF, separate stderr | `exec({ stdin })`, `session.closeStdin()`, `session.onStderr` | `SessionOpts { stdio: Some("pipes") }`, `WshSession::read_stderr()` / `close_stdin()`; `wsh host command` uses them whenever its stdin is a pipe or a file and the host offers `exec-pipes` | **Wire-unified, negotiated** (#105): `Open.stdio = "pipes"` + `OpenOk.stderr_channel_id` + zero-length `SessionData` as EOF, offered by the `exec-pipes` `ServerHello` feature. `@johnhenry/wsh/server` needs none of it (stream-mode EOF); the Rust `wsh-server` (`rust-v0.5.0`+) runs such an exec on pipes, everything else on the PTY. Against a host without `exec-pipes` the CLI still forwards stdin, but cannot tell the command it ended |
| Signals and resize for a one-off command | `session.signal()`, `session.resize()` | `wsh host command` forwards SIGINT/SIGTERM/SIGHUP (the same signal twice disconnects); `wsh --tty host command` also forwards terminal resizes | **Wire-unified** (`Signal`, `Resize`). **Not everywhere honoured**: the Rust `wsh-server` currently only logs `Signal`, so a forwarded signal does not stop the command there |
| Dial target | a URL | `wsh [user@]host` (dials `https://` then `wss://` on `--port`), or a full URL: `wsh wss://host:8443/rendezvous/ab12 command`, `ws://127.0.0.1:PORT/` | **CLI-only convenience**: a URL is dialled exactly as given (no transport fallback; `--port` and `--transport` do not apply). Plain `ws://` is accepted only to a loopback host |
| Host that runs in a browser page (`createMemoryHost`, `@johnhenry/wsh/reverse`) | yes, with injected `pty` / `fs` / `hostKey` | no (a Rust host is a process) | **JS-only**. A Rust *client* can operate such a host only with `dataStreams: false` (#132): the released Rust client over WebSocket cannot open QMux data streams, and says nothing in `Hello` that a host could use to decide. Its `scp` download also reads a raw stream, not the `FileChunk` messages this host sends, so `wsh scp` from such a host does not work (`wsh ls` and exec do) |
| Interactive shell UI | none -- this SDK is a protocol client, not a terminal emulator; pair with xterm.js/ghostty-web | `wsh connect`, `wsh sftp` (line-oriented REPL) | **Deliberately not unified** -- a browser embeds a terminal widget the host page owns; a CLI process owns its own TTY |
| Attach / resume | `attachSession()`, `resumeSession()`, `WshSession.seq` | `attach_session()`, `resume_session()` | **Wire-unified** (`Attach`/`Resume`/`Presence`); `seq` = cumulative output bytes. `@johnhenry/wsh/server` honours `last_seq` (bounded ring, gap errors) and answers Presence with `channel_id`/`seq`; the Rust `wsh-server` does the same (`rust-v0.2.0`+; fixed 256 KiB ring) |
| Reverse-connect / relay peer | `connectReverse()`, `trustRelayPeer()`; `@johnhenry/wsh/server`: `relay` option and `createReverseHost()` | `wsh reverse`, `wsh agent` (persistent, with startup-unit install) | **Wire-unified** (registration, discovery, signed peer records); **daemonization is CLI-only** -- a browser tab cannot be a background OS service. The Node relay is default-deny and bridges one operator per peer unless `maxOperatorsPerPeer` is raised (`busy:` reasons say so); E2E and bridged feature gates need `rust-v0.3.0`+ on the Rust side; several operators per peer and the signed `KeyExchange` are JS-relay only for now |
| Post-quantum E2E (experimental) | `initiateE2E()` (WebCrypto ML-KEM-768 or `@noble/post-quantum` fallback) | `E2eKeyExchange` (`ml-kem` crate) | **Wire-unified** algorithm and transcript; key material backends differ by platform necessity |
| Unix-domain socket forwarding, both directions; named endpoints (#120) | `client.openUnix()`, `listenUnix()`, `forwardUnix()` (Node: `-L`/`-R` shapes with unix and TCP ends mixed), `openEndpoint()`; host: `gateway: { unix, endpoints }`, `createMemoryHost({ endpoints })` | none yet (`wsh -L` / `-R` with sockets are not implemented) | **JS only for now.** Wire: `OpenUnix`, `OpenEndpoint`, `ListenUnix` behind the `gateway-unix` / `gateway-endpoints` host features; the Rust server and CLI must implement them (message handling, the path policy, `-L`/`-R` flags) as described under [Gateway](#unix-domain-sockets-streamlocal-and-named-endpoints) |
| Gateway flow control (#123) | credit per connection (`GatewayCredit`, feature `gateway-credit`); host caps for peers without it | none: the Rust forwarder has bounded in-process queues but no per-connection credit and no per-client byte cap | **JS only for now** (negotiated, so a Rust peer on either side keeps today's unmetered behaviour) |
| Gateway destination policy by resolved address | `@johnhenry/wsh/server` `gateway`: resolved address checked, `allowPrivate` | fixed in the Rust release after `rust-v0.6.0`: a loopback/private/link-local/ULA/CGNAT/unspecified/multicast address is refused after resolution unless a rule names it, and the server connects to the address it checked | **Same rule on both sides** (a Rust server released before that still has the name-only check) |
| Operator proof to the peer, sealed bridge, signed initiator half (#117) | `reverseConnect(.., { sealed, requirePeerProof })`; host `createReverseHost({ requireOperatorProof })`; relay lists `operator-proof` | none: the Rust relay neither carries `ReverseChallenge`/`ReverseProof` nor lists the feature, and the Rust agent/client send and answer neither | **Wire-unified, negotiated** (`ReverseConnect.features`, `operator-proof`, `e2e-sealed`); the Rust types are regenerated (and `ReverseConnect.features` is `None` there) but no Rust peer implements it yet |
| Channel binding of the login signature (#119) | `requireChannelBinding` (client and server); kinds `host`, `cert-hash`, `tls-exporter` | none: no Rust host offers one and the Rust client signs with an empty binding | **Wire-unified, negotiated** (`channel-binding:<kind>` features); a Rust client logging in to a JS host that requires it is refused |
| Pipe relay (#118) | `@johnhenry/wsh/pipe-relay` | none; the `wsh` CLI always dials `wss://<host>/` (#136), so it cannot reach `/r/<id>` -- it needs `--via` or to keep the URL path | **Deliberately a relay without wsh parsing** -- nothing to unify on the wire |
| `AuthOk.ttl` enforced, `token` opaque (#125) | `connectionTtlMs`; `client.authTtl` | `wsh-server` sends `session_ttl` (default 86400) and an HMAC token, neither enforced or checked | **Wire-compatible**: both fields are still sent (released peers require them); the JS host sends `ttl: 0` unless a limit is set |
| `clientEnv` allow-list (#126) | default `TERM`, `COLORTERM`, `LANG`, `LANGUAGE`, `LC_*` | the Rust server applies whatever environment the client sends | **JS host only**; wire unchanged |
| Session recording/replay | `SessionRecorder`/`SessionPlayer` (asciicast-v2-shaped JSON) | none | **JS-only** -- no current Rust consumer needs playback; the vocabulary is asciicast v2's, so a Rust port could share it |
| Self-signed cert pinning | `serverCertificateHashes` (WebTransport option) | N/A -- Rust dials a cert its own TLS stack already trusts, or `--generate-cert`'s self-signed cert out of band | **Deliberately not unified** -- this is a browser-specific WebTransport API shape, not a wire-protocol concept |

### Build and test

```sh
cargo build --workspace
cargo test --workspace
```

The Node-to-Rust cross-implementation tests (`test/rust/*.test.mjs`) spawn
the real `wsh-server` binary and drive it with this repo's own JS client --
they're kept out of the default `npm test` glob so JS-only contributors
never need a Rust toolchain. Build the release binary first (or set
`WSH_SERVER_BIN` to point at one), then:

```sh
cargo build --release -p wsh-server
npm run test:rust
```

### Codegen: regenerate, don't hand-edit

`crates/wsh-core/src/messages.gen.rs` is generated from `spec/wsh-v1.yaml`
by `spec/codegen.mjs`, alongside the JS (`src/messages.gen.mjs`) and
Markdown (`spec/wsh-v1.md`) outputs -- all three come from the same schema
and must never be hand-edited. After changing `wsh-v1.yaml`:

```sh
npm run codegen        # regenerate all three outputs
npm run codegen:check  # CI check: fails if any output has drifted from the schema
```

### Release binaries

Tagging `rust-vX.Y.Z` (or running the `Release Rust binaries` workflow
manually with a tag input) builds and publishes prebuilt `wsh-server` and
`wsh-cli` binaries for four targets to a GitHub Release:

- `x86_64-unknown-linux-gnu`
- `aarch64-apple-darwin`
- `x86_64-apple-darwin`
- `i686-unknown-linux-musl` (the target clawser's demo-linux guest image needs)

Each target produces two archives, each containing a single binary at the
archive root:

```
wsh-server-<target>.tar.gz   # binary: wsh-server
wsh-cli-<target>.tar.gz      # binary: wsh
```

plus one `SHA256SUMS` file covering every archive in the release. These
names are a stable contract other repos (clawser) pin and download by --
do not change them without coordinating downstream.

## Security model

wsh's protocol draws its line at authentication and message integrity: what
it guarantees is that a handshake and its messages are who and what they
claim to be. It does not guarantee confidentiality of every auth method, or
that a server's identity has actually been pinned yet -- both are called
out explicitly below rather than left to be discovered.

**What wsh guarantees:**

- **Auth transcript binding.** Challenge signatures cover
  `SHA-256("wsh-v1\0" || lp(username) || lp(session_id) || nonce || channel_binding)`,
  so a signature can't be replayed against a different session or relabeled
  to a different username. `channel_binding` is empty unless both ends agree
  on one (wsh #119): then it also names the connection (host key, pinned
  certificate, TLS exporter), so a relaying intermediary cannot reuse a
  signature -- but only against a host that requires it or a client that
  does; see [Channel binding](#channel-binding-tie-the-login-to-the-connection).
- **A relay need not be believed about who the operator is (opt-in).** With
  `requireOperatorProof` on the host and `sealed` on the operator, the host
  verifies the operator's own signature before `accept`, and acts only on
  sealed traffic, so a relay cannot stamp an identity, replay a login or inject
  an `Open`; see the table under
  [Operator proof and sealed bridges](#operator-proof-and-sealed-bridges-117).
  Not default, not available through the Rust relay, and no defence against a
  relay that drops traffic.
- **A pipe relay vouches for nothing.** With `createPipeRelay` the host
  authenticates the operator itself (see [A pipe relay](#a-pipe-relay-johnhenrywshpipe-relay-118)).
- **`AuthOk.ttl` and `token`.** The token is an opaque per-connection value
  with no authority; `ttl` is enforced when `connectionTtlMs` is set (else 0:
  no limit) -- do not read either as a session credential.
- **Client environment is an allow-list** (`clientEnv`, default `TERM`,
  `COLORTERM`, `LANG`, `LANGUAGE`, `LC_*`): a client cannot set `PATH`,
  `LD_PRELOAD` or `BASH_ENV` for a command your host runs through a shell
  unless you say so.
- **E2E through a relay is opt-in.** The relay carries `KeyExchange` /
  `EncryptedFrame` between a bridged operator and peer without being able to
  read the sealed frames. `KeyExchange` is unauthenticated unless the peer signs
  it and the operator asks for that (`initiateE2E(..., { verifyPeer })`; a
  `createReverseHost` signs by default): without `verifyPeer` a relay that
  substitutes keys is not detected (see the [relay section](#relay--reverse-mode)).
- **Signed peer records.** Reverse-mode registration is self-signed by the
  peer's identity key (the libp2p RFC 0002/0003 pattern), in a signing
  domain separate from the auth challenge. `listPeers()` verifies every
  entry client-side and reports a `verified` boolean, independent of
  trusting the relay.

- **The Node gateway checks where a connection goes, not only what it was called.** `gateway.allow` matches the name a
  client sent, and then the address it resolves to must be globally routable (or permitted by `allowPrivate` or an
  IP-literal rule); the connection is made to that checked address, and `ResolveDns` answers are filtered the same way.
  Unix-domain sockets (`gateway.unix`) and named endpoints (`gateway.endpoints`) are off unless configured, are listed
  paths or names only, and sockets the host creates are `0600`.

**What is still yours:**

- **What the gateway does NOT protect against.** A name that resolves to a *public* address is dialled as the client
  asked, so `allow: ['*']` is an open proxy to the internet for every authorized client. Through `socks` the proxy
  resolves the name, so the host cannot check the address (only IP literals are checked) and the proxy's own network
  is the egress. The path check for unix sockets is made just before the connect: a local user who can write to an
  allowed directory can still swap a path between the two, so list only directories that are not writable by others.
  A client may open any listed socket as the host's user; a socket that speaks a powerful API (the Docker socket is
  root on the host) is exactly as powerful for every authorized client, so list it only for clients you would give that
  access. Named endpoints run embedder code with the caller's identity (`who`) but the handler decides what that
  identity may do. A `wsh-server` built before the Rust release that followed `rust-v0.6.0` only matches the name, not the
  resolved address (see the Rust defaults above): do not expose such a binary with a `"*"` allow list.

- **Hybrid post-quantum E2E is experimental and not fully wired (in
  progress).** `initiateE2E(sessionId, 'X25519+ML-KEM-768')` combines
  X25519 ECDH with ML-KEM-768 via HKDF-SHA256, preferring native WebCrypto
  ML-KEM-768 (Node 24.7+) with the optional `@noble/post-quantum` pure-JS
  fallback, and falling back to classical X25519 automatically when the
  peer can't do hybrid (check the returned `hybrid` flag). The derived
  AES-256-GCM key is not yet wired to actual frame encryption by default --
  treat `initiateE2E` as key agreement, not confidentiality, unless you've
  separately confirmed the session has sealing enabled.
- **Host identity (TOFU) has a known, named gap (wsh #59).**
  `ServerHello.host_fingerprint` is the spec's formal host-identity slot:
  the SHA-256 fingerprint of a server's persistent Ed25519 host key, meant
  to be pinned across connections the way SSH pins a host key. **As of 0.19
  `@johnhenry/wsh/server` populates it** (with a signed proof of possession;
  see [Host key](#host-key-fingerprint--tofu)) and the JS client pins it
  (`expectHostKey`, `knownHosts`) -- but **no Rust `wsh-server` release does
  yet**, and the paragraph below still describes that Rust-side gap -- minting and
  persisting a server host keypair is a separate, security-sensitive
  feature, deliberately not bundled into this change. Both clients ship
  the store this field is for: `WshKnownHosts` (JS, `localStorage`-backed)
  and `KnownHosts` (Rust, `~/.wsh/known_hosts`-backed) have matching
  verify/add/remove/list semantics. Today, against every real server,
  both report every host as unverified for host-identity purposes; the
  Rust client additionally still falls back to `fingerprints[0]` (an
  *authorized client key* this server happens to have, not this server's
  own identity -- see `ServerHello.fingerprints`' doc comment in
  `spec/wsh-v1.yaml`) with a logged warning, for backward compatibility.
  Do not treat either store as a MITM defense until a server actually
  populates `host_fingerprint`. `serverCertificateHashes` (below) is a
  different, narrower mechanism -- it pins a certificate supplied *per
  connection*, not a persisted record of what a host presented last time.
- **Password auth has no confidentiality of its own -- it relies entirely
  on the transport.** `AUTH_METHOD.PASSWORD` sends the password as a plain
  string inside the `auth` control message (`client.mjs`'s `#performAuth()`
  calls `sendControl(authMsg({ method: AUTH_METHOD.PASSWORD, password }))`)
  -- there is no client-side hashing, salting, or key derivation before it
  goes on the wire. Its confidentiality is entirely a function of whether
  the underlying connection is encrypted: fine over `wss:`/WebTransport
  against a certificate the client actually trusts (CA-signed, or pinned
  via `serverCertificateHashes`), but sent in the clear if the connection
  is a plain, unencrypted `ws:`. Browsers block that combination from an
  `https:` page as mixed content (see "Pinning a Self-Signed Certificate"
  above), but nothing in this protocol or client stops a non-browser
  caller (Node, the Rust CLI) from dialing `ws://` directly. Prefer pubkey
  auth, or make sure the transport is actually encrypted, before sending a
  password. (The Rust `wsh` CLI refuses a plain `ws://` URL unless the host is
  loopback.)

### Rust `wsh-server`: what is off until you turn it on

An authorized key is a login, not a licence to use the machine as a network
position. From the Rust release after `rust-v0.6.0` the server's defaults are:

- **The gateway is off** (`[gateway] enabled = false`), and `gateway` is not
  advertised. Turning it on allows **no destination** until `allowed_destinations`
  lists some. `"*"` means any *public* destination: an address that is loopback,
  link-local (including `169.254.169.254`), private (RFC 1918), unique-local
  (`fc00::/7`), carrier-grade NAT (`100.64.0.0/10`), unspecified or multicast is
  refused **after the name is resolved**, whichever rule matched the name, unless
  a rule names that host (`"db.internal:5432"`) or address/range
  (`"10.1.0.0/16:5432"`, `"127.0.0.1:8080"`). The server connects to the address it
  checked, so a name cannot pass the check as one address and connect as another.
  `ResolveDns` follows the same rule and does not return internal answers.
- **Reverse listeners are off** (`enable_reverse_tunnels = false`) and, when on,
  bind to `reverse_bind_addr` (default `127.0.0.1`). The client's own `bind_addr`
  in `ListenRequest` (its wire default is `0.0.0.0`) is ignored.
- **Password login is off** (`[auth] allow_password = false`). Stored hashes are
  Argon2id PHC strings with a per-user salt (`printf '%s' "$PW" | wsh-server
  --hash-password`), compared in constant time; an unknown user and a wrong password
  cost the same and fail with the same message. Old unsalted `sha256:` entries are
  **refused** (logged at start-up, naming the user) unless `allow_legacy_sha256 = true`,
  which accepts them with a warning at every start-up. Refusing, not warning, is the
  default because a warning nobody reads leaves the weak hash live on every
  deployment that is not watched; the edit that turns password login back on is the
  natural moment to rehash.

What this does **not** protect against:

- **A rule you write is trusted.** A hostname rule (`"db.internal"`) allows that name
  to resolve to anything, including a restricted address; only the wildcard is
  held to public addresses. An address range or literal address rule allows
  exactly what it says.
- **It is not per-key.** Every authorized key gets the same gateway. A key that
  should not have it should not be in `authorized_keys`.
- **There is no bandwidth or request-rate limit** beyond `max_connections`
  (default 100 concurrent connections and listeners together), and a listener's
  port is chosen by the client within what the server's user may bind.
- **Hashing protects the stored file, not the wire.** The password still travels
  inside the auth message (see above); only use password login over `wss://` or
  WebTransport. The per-address auth rate limit bounds how fast one address can
  make the server run Argon2id (19 MiB each); it is not a defence against many
  addresses.
- **The dev certificate from `--generate-cert` is not a certificate a TLS client
  can verify** (it is flagged as a CA); clients dial it with
  `WSH_INSECURE_LOOPBACK_TLS=1`, which disables verification and is for loopback
  testing only.

- **A host that lives in a page (`createMemoryHost`, `@johnhenry/wsh/reverse`) is only as trustworthy as the page.** A
  non-extractable host key or client key keeps the private key from being *read*, not from being *used*: any script that
  runs in the page (an XSS, a malicious dependency, an extension with page access) can still have it sign, which means
  impersonate the host or log in as the user for as long as it runs. The injected `pty`, `fs` and `exec` backends are
  code you wrote and run with the page's authority -- wsh authenticates who may call them, and confines nothing about what
  they do: a file backend that resolves `..`, a `pty.spawn` that starts a real process, an `exec` that evals its
  command are yours to make safe (the Node server's `fs: { root }` is the one with confinement built in, and the
  browser-safe `fs` option takes no root). Pinning a page-held host key protects a client from the wrong host, not from
  a byte pipe or relay between them reading and altering the bytes: confidentiality needs `wss://` or the end-to-end layer.
  `dataStreams: false` changes how output is framed (as `SessionData`), not who is let in.

## Browser Compatibility

Requires a browser (or Node.js 24+) with `TextEncoder`/`TextDecoder`,
`ReadableStream`/`WritableStream`, `WebSocket` (universal), and:

### WebCrypto Ed25519 -- the real floor

This is what actually gates the library, because pubkey auth is not
optional to the protocol. Roughly: **Safari 17+, Chrome/Edge 137+,
Firefox 130+, Node 20+**.

There is deliberately **no pure-JS fallback**. A JS Ed25519 needs the
private scalar as ordinary bytes, which would give up the property
`WshKeyStore` is built around -- keys are non-extractable `CryptoKey`
objects by default, so a compromised page can *use* a key but cannot
exfiltrate it. Trading that away on exactly the oldest, least-patched
engines is the wrong direction, and doing it silently would be worse.

Ask before you commit to pubkey auth:

```js
import { isEd25519Supported } from '@johnhenry/wsh';

if (await isEd25519Supported()) {
  await client.connect(url, { username, keyPair });
} else {
  await client.connect(url, { username, password });
}
```

`isEd25519Supported()` measures by generating a key rather than sniffing a
version string, and memoizes. `generateKeyPair()` throws with an
actionable message where support is missing, rather than passing the
platform's "Unrecognized name" straight through.

### WebTransport

WebTransport is optional -- the transport ladder falls back to WebSocket.
It matters if you want `serverCertificateHashes` (see [Pinning a
Self-Signed Certificate](#pinning-a-self-signed-certificate)), which has
no WebSocket equivalent.

**Safari supports WebTransport, and more of it than Chromium does.**
That is the opposite of the usual assumption, and the earlier version of
this section propagated the assumption by listing only Chrome, Edge and
Firefox. Measured on 2026-09-04, both engines on a `localhost` secure
context:

| | `WebTransport.prototype` members | Ed25519 | X25519 | ML-KEM-768 |
|---|---|---|---|---|
| WebKit -- Safari 26.5, iOS 26.5 simulator | **17** | OK | OK | fails (`TypeError`) |
| Chromium 148, macOS | 10 | OK | OK | fails (`NotSupportedError`) |

WebKit's extra seven are `congestionControl`, `reliability`, `draining`,
`getStats`, `createSendGroup`, and the two
`anticipatedConcurrentIncoming*Streams` hints; both engines have
`datagrams`, both bidirectional and unidirectional stream creation, and
`ready`/`closed`.

Approximate first-support versions, which are *not* measured here: Chrome
and Edge 97, Firefox 114, Safari 26. Below Safari 26, the ladder falls
back to WebSocket.

Both engines accept a `serverCertificateHashes` entry without a
synchronous throw, but that is weak evidence on its own -- unknown WebIDL
dictionary members are silently ignored, so acceptance does not prove the
option is honoured. Confirming it needs a real HTTP/3 server presenting a
matching short-lived certificate.

### ML-KEM-768

The hybrid post-quantum path prefers native WebCrypto ML-KEM (Node 24.7+).
**No browser tested has it** -- it failed on both engines above -- so in a
browser the optional `@noble/post-quantum` dependency is what actually
runs, loaded dynamically by `src/mlkem.mjs`. Treat it as required, not
optional, if you want the hybrid handshake on the web today.

## Browser tests and bundle size

`npm test` is JS-only and needs no browser. `npm run test:browser` runs the real-Chromium suite (Playwright; install it
once with `npx playwright install chromium`) and has its own CI job:

- a browser client against a Node `createWshServer` over a real WebSocket: auth with a non-extractable key, exec, a pty with
  resize, file transfer, and resuming a session after the socket drops;
- a host that lives in the page, `createMemoryHost().accept(new WebSocket(url))`, joined to its operator by a tiny byte pipe
  the test owns, driven by the JS client (exec, stdin, pty, files, a pinned non-extractable host key) **and by the released
  Rust `wsh` CLI**: that test downloads the latest `rust-v*` release's archive for the platform from this repository's
  GitHub releases, verifies it against the release's `SHA256SUMS`, and runs it with `HOME` pointed at a temp directory (so
  it never touches `~/.wsh`). It is skipped, with the reason printed, on a platform with no release asset or when the
  download fails, and fails (rather than skips) in CI. The released CLI only dials `wss://`, so the pipe terminates TLS with
  a self-signed certificate and the CLI runs with its loopback-only `WSH_INSECURE_LOOPBACK_TLS=1`;
- `WshKeyStore` with a non-extractable key surviving a reload and still authenticating.

The bundle-size report is described under [Browser entry points](#browser-entry-points-the-connection-factory-and-bundle-size).

## Related projects

- **[`@johnhenry/browsermesh-netway`](https://github.com/johnhenry/browsermesh)** takes a `WshClient` as its gateway backend
  (see [Family](#family) below).
- **The Rust crates** in [`crates/`](crates) (`wsh-core`, `wsh-client`, `wsh-cli`, `wsh-server`) are a native
  implementation of the same wire protocol, versioned separately (`rust-v*` tags) and generated from the same
  `spec/wsh-v1.yaml`; see [Rust implementation](#rust-implementation) for what each side can do.
- **[clawser](https://github.com/erisera-code/clawser)** downloads the Rust release binaries by their archive names and is
  where the Rust workspace came from.

## Family

wsh isn't just a standalone remote-shell client -- its `WshClient` is the
designed transport backing one sibling package's network gateway, and
`WshClient`'s connected/authenticated shape is a drop-in for that sibling's
injected-client extension point.

- **[`@johnhenry/browsermesh-netway`](https://github.com/johnhenry/browsermesh)**
  -- browsermesh-netway's `GatewayBackend` takes a `wshClient` in its
  constructor and proxies every network operation (socket open/send/close)
  through it via `sendControl()`, once the client reaches the
  `'authenticated'` state (`isReady()` checks exactly that). This is a real,
  verified dependency on wsh's client shape -- `GatewayBackend` is
  duck-typed against a `WshClient` instance, not declared as an npm
  dependency -- not a thematic pairing; see
  `packages/browsermesh-netway/src/gateway-backend.mjs` in the browsermesh
  repo. wsh itself has no dependency in the other direction.

## License

MIT
