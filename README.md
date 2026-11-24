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
- **110 message types** -- handshake, channel, gateway, guest sharing, compression negotiation, copilot, policy, authorized-key management, and more. [`spec/message-matrix.md`](spec/message-matrix.md) says, for each, whether the JS host, JS client, Rust host and Rust client implement it (generated from the spec and the source; CI fails when it is stale), and [COMPATIBILITY.md](COMPATIBILITY.md) is the policy for changing the protocol without breaking a released peer

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

### Authorized-key options (#122)

`auth.authorizedKeys` takes `authorized_keys` lines with options, and reads them the way the Rust `wsh-server` does: **the same
key file gives the same answer on both hosts.** The two parsers share one set of test vectors
(`spec/key-options.vectors.json`: a key line gives these permissions, a request is allowed or refused with this code), run by the
JS suite and by a Rust test, so they cannot drift.

```
restrict,permit-exec,max-sessions=2  ssh-ed25519 AAAA... ci@build
command="/usr/bin/uptime"            ssh-ed25519 AAAA... monitor
no-pty                               ssh-ed25519 AAAA... alice
```

A line is `[options] ssh-ed25519 <base64> [comment]`. The options are one token (spaces only inside double quotes) of
comma-separated items, each `name` or `name=value`; a value is `"..."` (`\"` is a quote, any other backslash is literal) or, for
values without spaces, a bare word. Single quotes are not quotes. Names are case-sensitive.

| Option | Meaning | Node host (`@johnhenry/wsh/server`) | Rust `wsh-server` |
|---|---|---|---|
| *(none)* | full access: everything the host is configured to offer | as before | as before |
| `restrict` | grant nothing; add back with `permit-*` | all entries below | all entries below |
| `permit-pty` | a pty shell, and commands (a shell can run them) | `Open` kind `pty`, `exec` | `Open` kind `pty`, `exec` |
| `permit-exec` | `exec` channels | `Open` kind `exec` | `Open` kind `exec` |
| `permit-file-transfer` | file channels, `FileOp`, `wsh-fs` | `Open` kind `file` (upload, download), `FileOp`, rpc `wsh-fs` | the same |
| `permit-mcp` | MCP discovery and calls | `McpDiscover` (an empty list otherwise), `McpCall`, rpc `mcp` | `McpDiscover`, `McpCall` (no rpc `mcp`) |
| `permit-relay` | relay registration, listing and connecting | `ReverseRegister`, `ReverseList`, `ReverseConnect` (`relay`) | the same (`--enable-relay`) |
| *(any restriction)* | a key that is not wholly unrestricted may not install another key | no `AuthorizedKeyAdd` handler | `AuthorizedKeyAdd` (the installed line has no options, so it would otherwise mint an unrestricted key) |
| `no-pty` | no pty, even when otherwise permitted | `Open` kind `pty` | `Open` kind `pty` |
| `command="..."` | the only command the key may run; it replaces what the client asks for, and the key gets no pty, files, MCP, relay or rpc | `Open` (exec only), `FileOp`, rpc | the same |
| `max-sessions=N` (N >= 1) | at most N live pty/exec sessions for the key, over all its connections | counted on this host (detached hosted sessions too) | counted by the session manager |
| `no-agent-forwarding`, `no-port-forwarding`, `no-X11-forwarding`, `no-user-rc` | accepted, **no effect** (see below) | ignored | ignored |

Without `restrict`, the `permit-*` options change nothing. Another rpc protocol (one the embedder added) is open only to a key
that is not restricted at all; `wsh-host` is open to every key but a forced-command one.

**An option this host does not understand refuses the key**: it is not on the allowlist, and the reason is logged (the Node
host's `onLog`, the Rust server's log: `key refused ... code=unknown-option`). It is never skipped and then granted. The same
for a malformed value: `max-sessions=0` (it used to mean "no limit" on the Rust server), an empty `command=""`, an option given
twice, a stray comma. Refusal codes: `unknown-option`, `bad-syntax`, `bad-value`, `duplicate-option`. A line whose options
cannot be separated from the key (an unterminated quote) or whose key is not `ssh-ed25519` is skipped. If a key appears on
several lines the first decides.

`parseAuthorizedKeys(text)` still returns bare keys, and now only for lines **without** options (it never hands out a key with
its restrictions dropped); `parseAuthorizedKeyEntries(text)` returns `{ entries, refused }` with each key's permissions.

Not covered by `restrict` and the `permit-*` options (see [Security model](#security-model)): the **gateway** (TCP, DNS, unix,
endpoints, reverse listeners) and the **targets**, so `restrict` and `no-port-forwarding` do not stop a key from using a gateway
the host has turned on; scope them with `capabilities` below. `no-port-forwarding` is accepted for ssh compatibility and does nothing.

#### Capabilities and expiry (#122, step two)

Two more options give a key a finer, **default-deny** licence. Nothing changes for a key line that has neither.

```
capabilities="exec,fs:read,gateway:tcp:db.internal:5432,mcp:search"  ssh-ed25519 AAAA... ci@build
expires="2030-01-01T00:00:00Z"                                      ssh-ed25519 AAAA... contractor
```

`capabilities="a,b,c"` (comma-separated, no spaces) lists what the key may do; **once the option is present the key may do only
that**, on top of what its other options allow (the two are ANDed: `restrict,permit-exec,capabilities="exec,pty"` still has no
pty). `capabilities=""` is a key that may do nothing. `expires="<RFC 3339>"` (`2030-01-01T00:00:00Z` or with an offset; whole
seconds; upper-case `T`/`Z`) refuses the key from that second: at login, and for every request after it. An unknown capability, a
malformed argument or a bad timestamp refuses the key (logged with the code `unknown-capability`, `bad-capability` or
`bad-value`), as unknown options do.

| Capability | What it allows | Entry points (Node host / Rust `wsh-server`) |
|---|---|---|
| `exec` | `exec` channels | `Open` kind `exec` / the same |
| `pty` | a pty shell (does **not** imply `exec`) | `Open` kind `pty` / the same |
| `fs:read` | stat, list, read, download | `FileOp` `stat` `list` `read`, `Open` kind `file` download / the same |
| `fs:write` | write, mkdir, remove, rename, upload (does not read) | `FileOp` `write` `mkdir` `remove` `rename` (an op nobody knows is a write), `Open` kind `file` upload / the same |
| `gateway:tcp:<host>:<port>` | `OpenTcp` to that destination; also `ResolveDns` for a host that matches | the Node gateway / the Rust gateway |
| `gateway:udp:<host>:<port>` | `OpenUdp` to that destination | the same |
| `gateway:listen:tcp:<port>` | a reverse TCP listener (`ListenRequest`) on that port | `gateway.reverse` / `enable_reverse_tunnels` |
| `unix:<path>` , `unix:listen:<path>` | connect to, or listen on, that unix socket | `OpenUnix` / `ListenUnix` |
| `endpoint:<name>` | a named endpoint | Node host only: the Rust server has none and refuses every `OpenEndpoint`, whatever a key holds |
| `mcp:<tool>` | list and call that tool (`mcp:*`: every tool, and the `mcp` rpc channel) | `McpDiscover` lists only these, `McpCall` / the same |
| `target:<name>` | name that target in `Open`, `FileOp`, `OpenEndpoint`; `ListTargets` shows only these | Node host only: the Rust server has no targets and refuses a request that names one |
| `rpc:<protocol>` | open that rpc protocol (`wsh-host`, or an embedder's own) | `Open` kind `rpc` / the same |
| `relay` | register, list and connect through the relay | `ReverseRegister` `ReverseList` `ReverseConnect` / the same |

`<host>` is a name, an IP literal (IPv6 in brackets), `*`, or `*.suffix` (any subdomain, not the apex; the name is compared
case-insensitively as the client sent it, so resolution is the gateway's `allow` policy's business). `<port>` is a number or `*`.
`<path>` is absolute with no `.` or `..`, exact or ending in `/*` (anything below that directory). `<name>`/`<tool>` are exact or `*`.
The `wsh-fs` rpc channel puts read and write methods on one channel, so it needs **both** `fs:read` and `fs:write`; a client without
both falls back to `FileOp` and the file channels, which are checked per operation. A request with no target runs on the host's own
backends and needs no `target:` capability (use `requireTarget` to confine keys to targets). Installing a key (`AuthorizedKeyAdd`) is never
allowed for a key with a capability list. A custom `authorize` on `createWshServer` / `createMemoryHost` may return `{ capabilities,
expires }` instead of `true`: the same grammar, narrowing the key's own options (it never widens them).

Refusals name the missing capability (`missing capability fs:write`, `missing capability gateway:tcp:db.internal:22`) in the answer
the client already gets (`OpenFail`, a failed `FileResult`, `GatewayFail`, `ListenFail`, an MCP result, a relay `Error` /
`ReverseReject`, `AuthFail` for an expired key), and the Node host reports each one to `onRefused` with the stable reason
`not-permitted` (`detail`: `capability-missing: missing capability exec (open exec)`), or `key-expired`. The Rust server logs them.
`capabilities` and `expires` apply to **key logins**: a password login has no key and is not narrowed by them.

### Gateway (TCP and DNS egress from the host)

`gateway: { allow: ['broker.lan:1883'], allowPrivate: ['10.0.0.0/8'], socks: '127.0.0.1:9050' }` makes the Node server
answer the gateway opcodes, so a client (a browser tab via netway's `GatewayBackend`, or `client.openTcp()`) can open TCP
connections and resolve names from the host. Default deny; `allow` takes `"*"`, `"host"` or `"host:port"`. `socks` routes
every dial through a SOCKS5 proxy (Tor) with the name unresolved. `OpenUdp` and TCP reverse tunnels are served too, each
with its own bounds; both are described below.

#### UDP (`client.openUdp`), and WebTransport datagrams (#98, #124)

`client.openUdp(host, port)` opens a UDP flow to ONE destination, fixed when it is opened. The destination goes through the
same name rule and resolved-address policy as TCP (a loopback or private address needs `allowPrivate` or an IP-literal
`allow` entry, and `allow: []` is still default deny), the host's socket is `connect()`ed to the resolved address so the
kernel delivers nothing to it from any other address or port, and `socks` refuses UDP. The result has `send(bytes) =>
Promise<boolean>`, `readable`, `writable`, `close()`, `transport`, `maxDatagramSize` and `stats`. **Datagram semantics:** a
payload may be dropped (a rate limit, transport back-pressure, a receive queue that is full) and nothing says which; a
slow reader loses the newest datagrams past 128 queued, it does not make anyone buffer.

- **Over WebTransport, when both ends list `gateway-datagram`**, payloads are WebTransport datagrams: a 4-byte big-endian
  flow id (the `gateway_id` of the `OpenUdp`) and the payload, nothing else. They are not ordered and not retransmitted, so
  loss on one flow does not delay another, and `GatewayCredit` does not apply to them. `OpenUdp`, `GatewayOk`/`GatewayFail`
  and `GatewayClose` stay on the control stream. The client lists `gateway-datagram` in `Hello.features` when its transport
  has datagrams (WebTransport: browsers and `@fails-components/webtransport`); the host lists it in `ServerHello.features`
  when it is on WebTransport, its gateway serves UDP and `udp.datagrams` is not `false`.
- **The size limit is read, not assumed.** `maxDatagramSize` comes from the transport (`WebTransport.datagrams.maxDatagramSize`,
  which the platform defines as the largest datagram you may write; the host side uses the same property of the session, and
  senders use `createWritable()` where present and the deprecated `writable` otherwise). It is about 1.2 KB on a QUIC path
  (1207 payload bytes on a loopback test connection) and can change, so it is read again for every payload. A payload bigger than
  `maxDatagramSize - 4` is **sent on the reliable control stream by default**, in both directions, rather than lost: real
  UDP semantics would drop it (or IP would fragment it), but a tunnel that cannot carry a 1252-byte QUIC Initial or an
  unfragmented big DNS answer is not useful, and the cost (that one payload is ordered and retransmitted) is stated, counted
  (`oversizeReliable`) and bounded by the same rate limits. For strict semantics set `udp: { oversize: 'drop' }` on the host
  (an oversize reply is dropped and counted in `oversizeDropped`) and `openUdp(h, p, { oversize: 'drop' })` on the client
  (`send()` rejects with a `RangeError`, the sender's error). A payload over 65507 bytes is always a `RangeError`.
- **Over WebSocket, or against a host without the feature (every released host), or with `udp.datagrams: false`**, one
  `GatewayData` is one datagram on the reliable control stream as before: ordered, retransmitted, credit-metered. `flow.transport` says
  which path a flow uses.
- **Bounds** (`gateway.udp`, all with defaults): `maxFlows` 16 per client; `packetsPerSecondPerFlow` 500 and
  `packetsPerSecondPerClient` 2000, as token buckets over both directions; `bytesPerSecondPerClient` 4 MiB/s over both
  directions; a flow idle for `udpIdleMs` (default 60 s) is closed. A datagram over a limit is dropped and counted, never
  queued. `server.gatewayStats().udp` has the counters (`datagramsFromClient`, `datagramsToClient`, `rateDropped`,
  `oversizeReliable`, `oversizeDropped`, `unknownFlow`, ...).

#### TCP reverse tunnels (`client.listenTcp`, #98)

`gateway: { allow: [], reverse: { ... } }` lets a client ask the HOST to listen on a TCP port and be handed every connection
made to it (OpenSSH `-R`). This puts a port of the host on a network, so it is **off unless `reverse` is given** (a
separate switch from outbound use: `allow` has no say in it) and bounded:

```js
createWshServer({ auth, gateway: { allow: [], reverse: {
  bindAddr: '127.0.0.1',        // what the host binds, default loopback; the client's bind_addr is IGNORED unless listed in...
  allowBindAddrs: [],           // ...the addresses a client may pick (IP literals only). The default ListenRequest bind_addr, "0.0.0.0", is never honoured unless you list it.
  ports: [0, '1024-65535'],     // what a client may ask for (the default shown). A list you give REPLACES it: a port below 1024 only if you name it.
  maxListeners: 4, maxConnectionsPerListener: 16, backlog: 8, idleMs: 300000,
} } });
const l = await client.listenTcp(0, { onConnection: (duplex, { peer, peerPort }) => { /* web streams with backpressure */ } });
console.log(l.port);            // the port the host bound (the actual port for 0)
await l.close();
```

Each inbound connection is announced with `InboundOpen` (the real peer address and port), the client answers
`InboundAccept { gateway_id }` (or `InboundReject`), and data then flows exactly like any gateway connection, with the same
credit rules. Every refusal says why in the `ListenFail` text (`reverse tunnels are not enabled on this gateway`, `port 80
is not allowed by the reverse-tunnel policy (ports below 1024 must be listed ...)`, `too many reverse listeners (limit 4)`,
`address in use`). A connection over `maxConnectionsPerListener`, or over the client's `maxConnections`, is closed without
being announced; accepted connections idle for `idleMs` are closed; a connection nobody accepts within 30 s is dropped;
listeners and their connections close when the client goes away. The host advertises `gateway` (it lists no separate
feature for reverse tunnels, matching the Rust server), so against a host that has them off the answer is the `ListenFail`.

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

**Rust side.** The Rust `wsh-server` serves the same messages with the same policy (`[gateway]`, off unless
`enabled = true`; `gateway-unix` is advertised only when a socket is listed):

```toml
[gateway]
enabled = true
unix_connect = ["/var/run/docker.sock", "/run/user/1000/wsh/"]  # OpenUnix: exact path, "/dir/" prefix, or "@abstract" (Linux)
unix_listen = ["/run/user/1000/wsh/"]                            # ListenUnix: sockets a client may ask the host to create
unix_replace_stale = false      # replace a stale socket file only if the request asks AND this is true
unix_max_listeners = 4          # per client connection
max_buffered_bytes = 4194304    # per connection, for a peer without gateway-credit (at least 262144)
max_client_buffered_bytes = 33554432
```

The checks are the Node host's: paths judged after `realpath` of the parent, a `..` segment refused, the target must be a
socket and not a symlink, created sockets are `0600` and unlinked on close, a socket that something still accepts on is
never replaced, a file that is not a socket is never touched; a bad pattern (`/`, a relative path, `..`) stops the server
at start-up. `GatewayCredit` is served with 256 KiB per direction when the client lists `gateway-credit`; without it the
host closes a connection that has more than `max_buffered_bytes` of unconsumed client data (or the client more than
`max_client_buffered_bytes`). The `gateway_id` and `listener_id` tables are per client connection (before, one table was
shared by every client). A Rust host does not offer named endpoints.

The CLI forwards like OpenSSH (see [Rust implementation](#running-a-command-with-wsh)): `wsh -L /tmp/docker.sock:/var/run/docker.sock user@host`,
`wsh -N -L 2375:/var/run/docker.sock user@host`, `wsh -N -L /tmp/d.sock:endpoint=docker --via wss://relay/r/<id> user@host`.

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
work) against `scripts/bundle-budget.json`; CI runs it (and writes the table to the job summary) and `npm test` fails a
bundle more than 10% over its budget. `npm run size -- --update` rewrites the budget and the table below after a deliberate
change; CI fails when the table is not the budget's. Sizes are of this package's own code: `@noble/post-quantum`, the
optional ML-KEM backend, is left out of the measurement. What a page ships is what its bundler keeps of these
(`"sideEffects": false`; the single-import rows show how little a `generateKeyPair` or `createConnectionFactory` import pulls in).

<!-- bundle-size:start (generated by `npm run size -- --update`; do not edit) -->
| browser bundle | minified | gzip |
| --- | ---: | ---: |
| `@johnhenry/wsh` (whole entry point) | 159.1 kB | 47.8 kB |
| `@johnhenry/wsh/memory` (whole entry point) | 223.8 kB | 69.7 kB |
| `@johnhenry/wsh/host` (whole entry point) | 121.2 kB | 39.9 kB |
| `@johnhenry/wsh/reverse` (whole entry point) | 211.2 kB | 65.1 kB |
| `import { generateKeyPair } from '@johnhenry/wsh'` | 0.4 kB | 0.3 kB |
| `import { WshClient } from '@johnhenry/wsh'` | 131.2 kB | 39.1 kB |
| `import { createConnectionFactory } from '@johnhenry/wsh/host'` | 98.0 kB | 32.0 kB |
<!-- bundle-size:end -->

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
  (`busyPeerFull(n)`). The **Rust relay and the Rust peer do this too** (#93): `wsh-server --enable-relay`
  with `[relay] max_operators_per_peer = n` in its config (default `1`, 1 to 64; above 1 it advertises
  `relay-multi-operator`), and `wsh --max-operators n reverse ...` / `wsh --max-operators n agent run ...` on the
  peer (default `1`; the peer states the feature only to a relay that advertises it, and serves one operator at a
  time on any other). The Rust relay rejects a busy peer's next operator with a `ReverseReject` carrying the same
  `busy:` reasons. Differences from the JS relay, kept so nothing existing changes: when an operator leaves a peer
  that serves one, the Rust relay leaves the peer connected (it may take the operator back), where the JS relay
  closes it; and a peer that goes away leaves its operators connected. A Rust peer serving several operators keeps
  each operator's sessions, processes and files apart (when one leaves, only its work is killed), takes each
  operator's `--allow-operator` decision and operator proof on its own, and **does not seal bridges** (a
  connection holds one seal): `--max-operators` above 1 is refused together with `--require-operator-proof`, and
  an operator that insists on `--sealed` is refused by such a peer. The Rust relay also carries
  `KeyExchange.signature` and advertises `e2e-sign`, so a JS reverse host signs its half of an end-to-end
  exchange through it.
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
offer it there).

**Who is offered proof.** `ReverseConnect.features` is a field a released Rust host (`rust-v0.6` to `v0.8`) cannot decode
(`deny_unknown_fields`: it drops the connection, which looks like a timeout). So a peer lists `operator-proof` in its
registered capabilities when it can answer a challenge (JS hosts and, since `rust-v0.9`, Rust hosts with an identity),
`reverseConnect()` offers proof only to a peer whose record lists it (`proof: 'auto'`, looked up with `listPeers()`;
`peerCapabilities` skips the lookup, `proof: true` offers regardless, `proof: false` never), and the JS relay strips the
field for a peer that did not advertise it. `requirePeerProof` and `sealed` against such a peer fail at once with a
sentence and send nothing. A JS host from npm 0.36-0.38 does not list the capability yet, so proof to it needs an upgrade
of the host.

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

A Rust host (`wsh reverse`, `wsh agent run`) is in the right-hand column only with `--require-operator-proof`
and an operator that seals (`wsh reverse-connect --sealed`, or a JS operator with `{ sealed: true }`); with proof alone
a relay can still inject a plain `Open` stamped with the operator's fingerprint, exactly as the middle column says.
Not covered: an operator or host that skips the checks (the options are opt-in on both
sides; a host that does not require proof is exactly as exposed as before), the Rust `wsh-server` relay (it carries these
messages and seals nothing itself), and a compromised *operator* key (it proves the key, not the
person). A relay can still refuse service by dropping the challenge.

#### A sealed session (#155, host: JS and the Rust `wsh-server`; client: the JS client and the Rust CLI)

`createMemoryHost({ hostKey, dataStreams: false, sealSession: 'offer' | 'require' })` (and `createWshServer`, for a connection
accepted with `dataStreams: false`) seals the WHOLE session end to end. After login the client sends a `KeyExchange` whose
`session_id` is the connection's, signed with its login key and answered by the host with a signature of its host key (the
transcripts of the sealed bridge, bound to both identities and both ephemeral keys; hybrid X25519+ML-KEM-768). From then on every
message but the keepalive -- control messages, `GatewayData` for TCP / unix sockets / named endpoints, `GatewayCredit` -- is an
authenticated encrypted frame (`EncryptedFrame`, channel 0), so flow-control credit works as before. A plain message is not heard
once the session is sealed, and a frame that does not open (flipped bit, replay, reorder) closes it. Features: `e2e-session`
(offered), `e2e-session-required` (the host serves nothing on a session that is not sealed, and no password login). The Rust CLI
seals with `--sealed` (or on its own when the host says `e2e-session-required`) and refuses a host that does not offer it: no silent
downgrade. Only `--sealed` is a guarantee: sealing "on its own" rests on a `ServerHello` feature that a relay can strip before
login, so a client that must never talk in the clear passes `--sealed` (against a host that requires sealing, a stripped client is
refused, but what it sent before the refusal -- its commands, if any -- was already readable). What it does NOT cover: the handshake before login (the user name, the login public key and the host key proof are
readable by the relay; the signed key exchange is not secret), the sizes and timing of traffic, a host whose connection has client-opened
QMux data streams (not offered there), and a denial of service (a relay can always drop or cut).

The JS client is the initiator too: `client.connect(url, { sealSession: false | 'auto' | true })` (also `WshClient.exec`).
`'auto'`, the default, seals only against a host that says `e2e-session-required` (so a client written before this option keeps
talking plainly to a host that merely offers it, and a host that requires sealing no longer refuses it); `true` seals or fails --
a host that does not offer `e2e-session`, one that proved no host key, or a password login is refused BEFORE a credential is
sent, with a sentence; `false` never seals. `client.sessionSealed` says whether it is. The exchange is bound to the host key the
host PROVED on this connection: it authenticates that key, not whose it is, so pin the host as well (`expectHostKey` /
`knownHosts`), or a relay that presents its own host key and terminates the exchange is the host to this client. Once sealed, a
plain message from the host is dropped, a frame that does not open ends the connection (`onError`, then `onClose`), `openStream()`
is refused and datagrams are neither sent nor heard (UDP uses the reliable path). `'auto'` is not a guarantee, for the reason above;
`true` is.

The Rust `wsh-server` is a responder too: `[server] seal_session = "off" | "offer" | "require"` (default `off`: no feature is
advertised and no released client is affected; `offer` and `require` need `host_key`, else the config is refused at start). On a
WebSocket connection it advertises `e2e-session` (and `e2e-session-required` with `require`), and after a KEY login it answers the
signed key exchange (it verifies the login key's signature, signs its reply with the host key) with the same `SealGate` the CLI uses;
from then on every control message but ping/pong is an `EncryptedFrame` both ways, gateway data included, and a frame that does not open
closes the connection. `offer` serves a client that never asks as before. `require` serves nothing in the clear: a plain message before
the key exists is answered with an error and the connection is closed, a password login is refused, and WebTransport connections and
WISP tunnels are refused (they cannot be sealed; connect over WebSocket). **Typed rpc channels (`wsh-fs`, ...) are not offered while
`seal_session` is on** (they ride client-opened data streams, which are not frames; the server says so at start). WebTransport on an
`offer` server is served as before and does not list `e2e-session`, so a client that must seal (`sealSession: true`, `--sealed`) is
refused there before a credential is sent. The same limits apply as for the JS host: the handshake before login, sizes and timing,
and a denial of service are not covered, and sealing "on its own" (`'auto'`, the CLI without `--sealed`) against an `offer` server is
not a guarantee. Pin the server's host key on the client (`expectHostKey`, `known_hosts`): the exchange authenticates the key the server proved.

#### Knowing who a host turned away: `onRefused` (#163)

`createMemoryHost`, `createWshServer` and `createReverseHost` take `onRefused({ reason, who, detail })`, called once per
connection the host turned away, so an embedder can tell the user why a terminal was refused without parsing `onLog`. `reason`
is a stable code, the list is exported as `REFUSAL_REASONS` from `@johnhenry/wsh/host`: `not-sealed` (a plain client on a
host that requires a sealed session, or a password login there), `unauthorized` (a key the host does not allow, a wrong
password, or an operator a reverse host's `accept` turned down), `binding-required`, `bad-signature`, `method-disabled`,
`rate-limited`, `bad-request`, `seal-failed` (a sealed session's key exchange failed or a frame did not open), and for a reverse
host `busy`, `proof-required`, `proof-failed`. `who` holds what is known: `username`, `fingerprint` (a key login), `address` (when
the transport gives one); a refusal before the login names no one. `detail` is human text and not stable. New codes may be added;
none is renamed. It reports only what this host decided: it does not say what a relay in the middle dropped, a client
that never reached the host, or a frame the host silently ignored on an already-sealed session (a plain message after sealing
is dropped, as before, without a report).

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
(per-session `initiateE2E`, or the **sealed session** below); it cannot forge the operator's signature or the host's.
**Until you seal the session, treat a pipe relay as trusted for secrecy AND integrity**: it can read every control message and
all gateway and endpoint data (`GatewayData`: TCP, unix sockets, named endpoints) and alter forwarded bytes after the handshake
(#155; the JS client's `sealSession: true` and the CLI's `--sealed` seal it against a JS host that offers it). Pin the host key, require channel binding, use `wss://` to a relay you trust, or seal the session. It can drop, delay or
cut a connection, and it sees who dials which id and how much they send.

*CLI side (#145).* `wsh --via wss://relay/r/<id> user@host [command...]` dials the operator side
(`pipeUrl(relay, id)`; the URL must end in `/r/<22-128 base64url characters>`, may sit under a base path, and must not
be the `?role=host` URL). `user@host` stays the identity: the host key is recorded in `~/.wsh/known_hosts` under
`host:port` of that target (`--port`, default 4422), the key a direct connection uses, so the same host is the same
host whichever relay carried it and a different host behind that name is refused (`HOST KEY CHANGED`) before any
command is sent. A plain URL target (`wsh alice@wss://relay/r/<id> ...`) also dials but is recorded under the URL's
authority, which is the relay's, so prefer `--via`. `--via` works with `wsh [user@]host`, `connect`, `scp`, `ls`, `sftp`
and `copy-id`; it is an error elsewhere, and cannot be combined with a URL target. A pipe relay is WebSocket only: no
fallback, and `--transport` does not apply. The rendezvous id is not written to `last_session.json`, and the CLI never
prints it: errors and `--verbose` logs show the relay's host and the id shortened to its first characters
(`wss://relay/r/AbCd...`). The Rust client verifies the host-key proof and binds the login to it, as on a direct
connection; what it does not do (seal the pipe-relayed session) is listed under the Security model. The host side
is any process that can open a WebSocket to `pipeUrl(..., 'host')` and hand it to `accept`.

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

### `wsh-mcp`: a stdio bridge for MCP clients (#127)

An MCP client (Claude Desktop, Cursor, an SDK `StdioClientTransport`, ...) launches a command and speaks MCP over its stdio. The package
ships one, `wsh-mcp`, that connects to a wsh host, opens its `mcp` [rpc channel](#rpc-channels-object-mode) and passes the messages
both ways, verbatim (ids, notifications, progress, cancellation). The host serves it with
`createWshServer({ rpc: { mcp: mcpServerAdapter(server) } })` or, in a page, `createMemoryHost({ rpc: { mcp } })` (reach a memory host
through whatever carries its WebSocket or a [pipe relay](#a-pipe-relay-johnhenrywshpipe-relay-118)); give each channel its own server with a factory
(`mcpServerAdapter(() => makeServer())`) so a reconnect is served.

```
npx -p @johnhenry/wsh wsh-mcp [options] [user@]<url>        # or install the package and run `wsh-mcp`

  -l, --user NAME          login name (default: the user@ in the URL, $WSH_USER, $USER, the OS user)
  -i, --identity FILE      Ed25519 private key (default ~/.wsh/keys/default.pem, what `wsh keygen` writes; a PKCS#8 PEM works too)
      --channel NAME       the rpc channel to open (default mcp)
      --host-key KEY       pin the host (hex fingerprint or ssh-ed25519 line); unpinned, it warns on stderr
      --no-reconnect, --reconnect-attempts N, --timeout MS
```

An MCP client configuration:

```json
{ "mcpServers": { "remote": { "command": "wsh-mcp", "args": ["--identity", "/home/me/.wsh/keys/default.pem", "--host-key", "<fingerprint>", "wss://host.example:4422"] } } }
```

stdout carries MCP messages only (one JSON-RPC message per line); every diagnostic goes to stderr. Exit status: `0` the client closed
its side, `1` the host was lost for good, `2` it could not start -- no connection, a refused login or host key, or **a host that offers
no such channel** (the error lists the channels it does offer and how to serve one). After a dropped connection it reconnects (5
attempts from 500 ms, doubling), re-sends the client's `initialize` to the new channel without telling the client, answers a request
that was in flight with a JSON-RPC error (`-32603`, the client may retry) and delivers what the client sent meanwhile (at most 200
messages). `--target` is not offered: rpc channels are not per target on any host (#121). The same bridge is a function,
`runMcpStdioBridge()` from `@johnhenry/wsh/mcp-stdio`.

**Rust: `wsh mcp`** does the same without Node (the next `rust-v` release):

```
wsh mcp [options] [user@]host|URL      # a ws://, wss:// or https:// URL works as the target, as everywhere in wsh
  -i, --identity NAME     the key to log in with: a name in ~/.wsh/keys (what `wsh keygen NAME` makes), default "default"
      --channel NAME      the rpc channel to open (default mcp)
      --host-key KEY      pin the host: 64 hex digits or an ssh-ed25519 line; it must prove that key, known_hosts is neither read nor written
      --no-reconnect, --reconnect-attempts N, --timeout MS
      --via URL           through a pipe relay, as for every command that dials one host
```

```json
{ "mcpServers": { "remote": { "command": "wsh", "args": ["mcp", "-i", "default", "--host-key", "<fingerprint>", "me@host.example"] } } }
```

Behaviour, exit statuses, reconnect, the held-message bound and `stdout` carrying MCP only are as above. What differs from `wsh-mcp`:
the identity is a keystore name (`-i`), not a file; without `--host-key` the host is checked against `known_hosts` like every `wsh`
command (a first use is refused unless `--accept-new-host-key`, because stdin is the MCP stream and cannot answer a prompt; a key
that changed is always refused); `--target` is refused with the usual message. **The Rust `wsh-server` offers no `mcp` rpc channel**
(hosting an MCP server is an embedding concern), so `wsh mcp` against it exits 2 with `offers no "mcp" channel (it offers: wsh-host)`;
`wsh tools` reaches the tools a `wsh-server` is configured with (`[[mcp.tools]]`). Against a released `wsh-server`, `wsh mcp --channel
wsh-host` works (it is the same rpc channel, and a handy check). Not covered: a sealed session (`--sealed`) carries no rpc channels
on any host, so `wsh mcp --sealed` is refused; WebTransport (`https://`) opens the channel's stream but the Rust client has only
been run against WebSocket hosts.

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

### Execution targets (#121)

A host that fronts several places to run things (containers, VMs, workers, sandboxes) names them, instead of overloading `username` or
prefixing the command. Off unless you give `targets` (to `createWshServer`, `createMemoryHost`, or `createConnectionFactory` through
`resolveBackends`); then the host advertises `targets` in `ServerHello.features`.

```js
createWshServer({
  auth: { authorizedKeys },
  targets: {
    web: { description: 'the web container', exec: true },
    db:  { description: 'the database VM', exec: (command, io) => runInVm(io.target, command, io), fs: dbFiles,
           authorize: (who, { target, kind }) => who.fingerprint === DBA_KEY }, // kind: exec | pty | file | endpoint | list
  },
  // requireTarget: true,  // an Open, FileOp or OpenEndpoint that names no target is refused: nothing runs on the host itself
});
const targets = await client.listTargets();   // [{ name, description?, capabilities }] -- only what THIS key may use
await client.openSession({ type: 'exec', command: 'psql -c ...', target: 'db' });   // also exec(url, cmd, { target })
await client.fileOperation('list', '/var/lib', { target: 'db' });                    // FileOp.target
await client.openEndpoint('metrics', { target: 'web' });                             // OpenEndpoint.target
```

Each target has its own `exec`, `pty`, `fs` and `endpoints` (the same forms as the host's own, `exec: true` and `fs: { root }` included on
Node); the host's own are used only by a request that names no target. A target without a backend for the request refuses it (`exec is
not enabled for this target`): a request is never run somewhere else. `io.target` (exec), `{ target }` in the pty `spawn` options, in every
file backend call and on an endpoint's `duplex.target` tell a shared function which target it serves. `authorize(who, { target, kind })` is
asked for every request that names the target and for `listTargets()`; only `true` lets the caller on, and a refused target and one that
does not exist get the same answer (`no such target`), so the reply does not say which targets exist. A target without `authorize` is open
to every key the host authenticated, as the host's own `exec` is. A `target` the client sends to a host that does not advertise `targets` is
not sent (the client throws); a raw one is refused (`this host has no targets`). `createReverseHost` takes no `targets`.

What it does **not** do: `requireTarget` covers `Open` (exec, pty, file, rpc), `FileOp` and `OpenEndpoint`, not the gateway (`OpenTcp`,
`OpenUnix`, `ListenRequest`, ...), MCP, the `rpc` channels (`wsh-fs`, ... are the host's own and are refused when a target is named), or
`Attach` to a session that already exists (it was opened on its target, and its owner may attach as before). A target is an authorization
boundary only as far as your `authorize` and your backends make it one: the library routes and refuses, it does not isolate anything.

The Rust CLI names one with `wsh --target NAME [user@]host [command...]` (or `wsh --target NAME connect [user@]host`) and lists them with
`wsh targets [user@]host [--json]`; `--target` is refused (exit 2) by file transfer, forwarding, `--share`, `-N` and every other subcommand,
and sent only to a host that advertises `targets`. The Rust `wsh-server` has no targets (it states no feature and refuses any request that
names one).

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
| `wsh-fs` | `stat`, `list` (entries sorted by name in UTF-16 code-unit order on every platform and on both hosts: upper case before lower case, whatever the filesystem's case rules), `mkdir`, `remove`, `rename { path, newPath }`, `write { path, data, offset? }`, `upload { path, data, offset? }` (offset omitted/0 creates or truncates, later offsets continue in place: chunk big files), `read { path, offset?, length? }` and `download { path }` (the bytes arrive as `$/progress` chunks of at most 64 KiB; the result is `{ size, offset, length, eof }`). Same confinement as `fs`: no traversal or symlink escapes, `readOnly`, `maxFileBytes`; policy refusals are `-32003`. |
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
and `hostFingerprint: null` unless `[server] host_key` is configured. The JS client
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
| `MSG` | 110 message type constants (hex opcodes) |
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

Four crates, workspace-versioned (currently `0.15.0`):

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

`wsh --target NAME [user@]host [command...]` runs on one of the host's execution targets and `wsh targets [user@]host` lists the ones this key may
use (see [Execution targets](#execution-targets-121)); it is sent only to a host that advertises `targets`.

### Forwarding with `wsh -L` / `-R` / `-N`

Modelled on OpenSSH. The forwards live as long as the connection does (`wsh -L ... user@host` also runs the command or
shell; `-N` only forwards, until Ctrl-C), work with `--via` (the pipe relay carries them like anything else), and may be
repeated:

```sh
wsh -L 8080:db.internal:5432 alice@host                  # [bind_addr:]port:host:hostport  (the HOST connects to db.internal)
wsh -N -L /tmp/docker.sock:/var/run/docker.sock alice@host     # local unix socket -> a unix socket on the host
wsh -N -L 127.0.0.1:2375:/var/run/docker.sock alice@host       # local TCP port -> a unix socket on the host
wsh -N -L /tmp/db.sock:db.internal:5432 alice@host             # local unix socket -> TCP the host reaches
wsh -N -L /tmp/docker.sock:endpoint=docker --via wss://relay/r/<id> alice@tab.example   # a NAMED ENDPOINT of an in-page host
wsh -N -R /run/user/1000/wsh/app.sock:127.0.0.1:3000 alice@host # the HOST listens on a unix socket; connections come here
wsh -N -R 9000:localhost:3000 alice@host                        # the host listens on a TCP port (loopback by default)
```

A named endpoint is written `endpoint=NAME` as the remote end of `-L` (`NAME`: letters, digits, `.`, `_`, `-`; at most 64).
The `=` cannot occur in a host name, a port or a path, so it can never be mistaken for a host called "endpoint" (that is
`endpoint:80`), and `@NAME` is already the Linux abstract-namespace socket (`-L 8080:@name`). A host with no file system
(an in-page host) offers endpoints instead of unix sockets; `wsh -L ...:endpoint=docker` plus `DOCKER_HOST=unix:///tmp/docker.sock`
is the shape of reaching a daemon behind one. `-R` cannot name an endpoint (a host offers those, it does not listen on them).

Local TCP listeners bind `127.0.0.1` unless `bind_addr` says otherwise (`*` or `0.0.0.0` listens on every interface, and `wsh`
warns). Local unix sockets are created `0600`, removed on exit (a killed `wsh` leaves its file), and an existing file at the
path is **refused** unless `--replace-socket` is given, which replaces only a stale socket: never a live one, never a file that
is not a socket. With `-R`, `--replace-socket` asks the host to replace its own stale socket (its policy decides). A host that
cannot do what a forward needs says so (`this host does not offer unix-socket forwarding`, `no such endpoint`, `not allowed by
the gateway policy`); a malformed spec exits with status 2 before anything is dialled. Up to 128 forwarded connections are
open at once. `-L`/`-R`/`-N` apply to `wsh [user@]host [command...]` and `wsh connect` only.

### Sharing a directory with the host: `wsh --share` (#159)

A host with no disk of its own (a browser tab) sometimes needs files that live on the OPERATOR's machine: `docker run -v
$PWD:/app` through `wsh -L /tmp/docker.sock:endpoint=docker` is the case that asked for this. `--share` offers a directory of
THIS machine to the host for the life of the session; the CLI serves file operations on it, and nothing else.

```bash
wsh -N --share src=/home/me/project --share out=/home/me/build:rw --via wss://relay/r/<id> alice@tab.example
wsh -N -L /tmp/docker.sock:endpoint=docker --share app=$PWD alice@tab.example   # one connection, both
```

`--share NAME=/abs/dir[:ro|:rw]`, repeatable (at most 16; `NAME`: letters, digits, `.`, `_`, `-`, at most 64). **Read-only unless
`:rw`.** The path must be absolute and an existing directory, or the CLI exits with status 2 before dialling. It says once, on
stderr, what it shares and how (`wsh: sharing "src" = /home/me/project (read-only)`). It works with `-N`, `-L`, `--via` and a
command, applies to `wsh [user@]host [command...]` and `wsh connect` only (`scp`, `ls`, `sftp`, `copy-id` refuse it), and fails
with a sentence when the host does not say it can use shares: a share that silently does not exist is worse than none. Unix only.

**The path is sent too (#164).** The offer carries each share's root as an absolute path, as you typed it (made tidy: `//`, `.`
and a trailing `/` removed; `..` is left as typed), so a host that was asked for `-v /home/me/project:/in` can recognise the share
it belongs to (`fs.root`) instead of a hash in the share name. It is advisory (see [Security model](#security-model)): the host
cannot verify it. To keep your directory layout to yourself add `--share-hide-path`: the offer then has no path (exactly what
0.40.0 / `rust-v0.11.0` clients sent), `fs.root` is `undefined` on the host, and everything else works.

**What the host can do.** Stat and lstat, readdir (every entry WITH its attributes, in pages), readlink, open and read (ranges; a
small file's content rides the open, so reading it is one message), write, create, mkdir, rename, unlink, rmdir, setattr (mode,
times, truncate) and close, each a bounded `ShareRequest` the host sends and the CLI answers with an errno-like code. At most 16
requests are in flight (the rest are refused `EAGAIN` at once), no data in a request or reply exceeds 256 KiB, a stalled host
cannot make the CLI queue more than a few replies, at most 64 files are open at once, and the session's total read-plus-write rate
is capped (256 MiB/s after a 32 MiB burst). The host's own API is [`onShare(name, fs, who)`](#serving-the-operators-files-from-a-host-onshare).

**What it will not do, whatever the host sends** (each rule has a test that fails when it is broken; see the Security model):
the share exists only because it was named on the command line (nothing a host sends adds or widens one); every path is resolved
component by component from a directory descriptor opened at start-up, with `O_NOFOLLOW` on each step, so a symlink in the middle
of a path is `ELOOP` and one swapped in between a check and its use is never followed; `..` is refused; a symlink is only ever
seen as a symlink; sockets, devices and FIFOs do not exist (and a FIFO cannot hang the CLI); names that are not valid UTF-8 are
skipped; another file system mounted inside the tree is not entered; the root's device and inode are re-checked before every
request, so a root that was moved or replaced answers `ESTALE`; a file with more than one hard link is never opened for writing,
truncated or chmod'ed; a created file or directory gets the requested mode limited to `0755`'s bits (never setuid, never
group- or other-writable), created with `O_EXCL` so a link planted in its place is never written through; there is no operation
that makes a link. Case-insensitive file systems (the macOS default) cannot be used to reach outside: confinement is by
descriptor, never by comparing names, so `LINK` is the same symlink as `link` and is refused like it.

**Not done:** change notification (the host re-reads; nothing is cached on the CLI's side), Windows (`--share` is unix-only), a
Rust host that uses shares (the JS host does), and sharing over `wsh reverse-connect` (a direct or pipe-relayed session only).

#### Serving the operator's files from a host: `onShare`

```js
const host = createMemoryHost({
  auth, hostKey: true, dataStreams: false,           // a page host, reached through a pipe relay
  onShare: async (name, fs, who) => {                // once per share the operator's CLI offers
    if (name !== 'app') return;
    const entries = await fs.readdir('/');           // [{ name, type, size, mode, mtimeMs, ... }] -- attributes included
    const pkg = JSON.parse(new TextDecoder().decode(await fs.readFile('/package.json')));
    if (fs.writable) await fs.writeFile('/out/built.txt', new TextEncoder().encode('done'));
    if (fs.root === '/home/me/project') { /* a request for `-v /home/me/project:/in` is this share */ }
  },
});
```

`fs.root` (a string or `undefined`) is the directory's path on the operator's machine, as the operator typed it (#164). **It is
advisory and unverified**: the operator's client sends it, the host cannot check it, and the CLI still enforces the real
boundary (it serves only the directory it opened, whatever the path says). It is `undefined` when the client is older, sent
`--share-hide-path`, or sent something the host does not accept: the host keeps a path only if it is an absolute string of at
most 4096 bytes without a NUL and `paths` has exactly one entry per share; anything else is ignored, never an error. Use it to
recognise a share, not to decide what is safe.

`createMemoryHost`, `createWshServer` and `createReverseHost` take `onShare`; listing it makes the host state the feature
`shares`, and a host without it never hears an offer. `fs` is an object of async operations (`stat`, `lstat`, `readlink`,
`readdir`, `open` / `create` returning a file with `read(offset, length)` / `write` / `setattr` / `close`, `readFile`,
`writeFile`, `mkdir`, `rename`, `unlink`, `rmdir`, `setattr`, `truncate`, `chmod`, `utimes`), `fs.writable`, `fs.signal`
(aborted when the operator goes), `fs.stats` (requests, replies, bytes: the evidence that batching works), and the
`operate` / `readWhole` / `writeWhole` / `writeAt` shape of an injected [`fs` backend](#in-memory-host-johnhenrywshmemory), so a share can be served on.
Errors are `ShareError`s with `.code` (`ENOENT`, `EROFS`, `ELOOP`, `EPERM`, `EEXIST`, ...). The host keeps to the window the
CLI offered, gives every request a deadline (30 s), treats a reply that is too big or the wrong shape as `EIO`, and rejects every
pending call when the connection ends. Browser-safe: `src/shares.mjs` imports nothing from `node:*`.

### Capability matrix: JS SDK vs Rust CLI/client

Two implementations of one protocol will always have *some* asymmetry --
the question wsh #59 asks is whether it is visible and deliberate, or
discovered by accident. This table is that answer, made explicit rather
than left to be found.

| Capability | JS SDK (browser) | Rust CLI/client | Unified via |
|---|---|---|---|
| Directory listing (`list`) | `WshFileTransfer.list()` | `wsh_client::file_transfer::list()`, `wsh ls`, `wsh sftp` | **Wire-unified**: `FileOp`/`FileResult` with the generated `FileEntry` type (wsh #59) -- both languages decode the same shape, including symlink targets |
| Upload/download | `WshClient.upload()`/`.download()` | `file_transfer::upload()`/`download()`, `wsh scp` | **Wire-unified**: `FileChunk` over a `'file'`-kind channel (wsh #13). Before the Rust client of the next `rust-v` release (#140) it read a raw stream (an 8-byte size, then the data) that no host sends, so `wsh scp` hung against every host (JS and `wsh-server`); the CLI is now tested against a Node host through a pipe relay and against `wsh-server` (`test/rust/wsh-cli-scp.test.mjs`), uploads and downloads of 0 B to 300 KiB |
| Remove a remote file | `WshClient.fileRemove()` | `file_transfer::remove()`, `wsh sftp`'s `rm` | **Wire-unified**: `FileOp`/`FileResult` (`op: "remove"`) -- refused today by every `wsh-server` release ("not yet implemented"), the same refusal on both sides |
| Install an authorized key | `WshClient.addAuthorizedKey()` | `wsh_client::WshClient::add_authorized_key()`, `wsh copy-id` | **Wire-unified** (wsh #59): `AuthorizedKeyAdd`/`AuthorizedKeyResult`, replacing a Rust-CLI-only shell command with a message every implementation can send |
| Host identity / TOFU | `WshKnownHosts` (localStorage-backed) | `KnownHosts`/`HostStatus` (`~/.wsh/known_hosts`-backed); the client sends `host-key-nonce`, verifies `host-key`/`host-key-sig`, pins only a proven key, and a first use needs `--accept-new-host-key` or a yes at a terminal (`--require-host-key` refuses a host with no proof); `wsh-server` has an opt-in host key (`[server] host_key`) | **Unified** (wsh #59, #145): both pin a PROVEN `ServerHello.host_fingerprint`. A Rust server with no `host_key` configured (the default, so released clients keep working) proves nothing |
| Typed RPC channels (`openRpc`, `rpc` sessions; `wsh-host`, `wsh-fs`, `mcp`) | `WshClient.openRpc()`, `RpcChannel` | Rust `wsh-server` (`rust-v0.4.0`+): `wsh-host`, and `wsh-fs` when `[rpc] fs_root` is set. **Client:** `WshClient::open_rpc(protocol)` in `wsh-client` (the next `rust-v` release; #127) returns an `RpcChannel` that sends and receives JSON-RPC messages (`rpc_offer()` tells what the host serves); it opens the channel's data stream over WebSocket/QMux (and WebTransport, not exercised against a host) and enforces `rpc-max-message`. It does not correlate requests or interpret `$/cancel` / `$/progress` (its one user, `wsh mcp`, passes MCP through), and there are no typed `wsh-fs` helpers in Rust (the Rust file commands use `FileOp`) | **No wire change**: `Open { kind: 'rpc', command: <protocol> }` plus `rpc*` `ServerHello` features, negotiated so it fails fast elsewhere; the Rust server serves it on WebSocket/QMux only. (`rpc` is now listed in the spec's `ChannelKind`; the bytes are what they were, the Rust server already read the kind from the raw message) |
| MCP over stdio for MCP clients that launch a command (#127) | `wsh-mcp` (the package's `bin`) and `runMcpStdioBridge()` from `@johnhenry/wsh/mcp-stdio`: opens the host's `mcp` rpc channel, reconnects, a clear error when the host offers none | `wsh mcp [user@]host\|URL` (the next `rust-v` release): the same bridge, behaviour for behaviour (`--channel`, `--host-key`, reconnect with `initialize` replayed, in-flight requests answered with an error, 200 held messages, exit 2 with the channels the host offers). Identity is `-i NAME` (a `wsh keygen` key), the host is pinned by `known_hosts` or `--host-key`, `--via` works. **`wsh-server` serves no `mcp` rpc channel, so `wsh mcp` to it exits 2 and says it offers `wsh-host`** (use `wsh tools` there: it answers `McpDiscover` / `McpCall`) | **Unified** -- no wire change (the channel is #85's); tested against a Node host and a memory host with the MCP SDK's stdio client (`test/rust/wsh-mcp.test.mjs`) |
| Exec stdin + EOF, separate stderr | `exec({ stdin })`, `session.closeStdin()`, `session.onStderr` | `SessionOpts { stdio: Some("pipes") }`, `WshSession::read_stderr()` / `close_stdin()`; `wsh host command` uses them whenever its stdin is a pipe or a file and the host offers `exec-pipes` | **Wire-unified, negotiated** (#105): `Open.stdio = "pipes"` + `OpenOk.stderr_channel_id` + zero-length `SessionData` as EOF, offered by the `exec-pipes` `ServerHello` feature. `@johnhenry/wsh/server` needs none of it (stream-mode EOF); the Rust `wsh-server` (`rust-v0.5.0`+) runs such an exec on pipes, everything else on the PTY. Against a host without `exec-pipes` the CLI still forwards stdin, but cannot tell the command it ended |
| Signals and resize for a one-off command | `session.signal()`, `session.resize()` | `wsh host command` forwards SIGINT/SIGTERM/SIGHUP (the same signal twice disconnects); `wsh --tty host command` also forwards terminal resizes | **Wire-unified** (`Signal`, `Resize`). The Rust `wsh-server` delivers `Signal` (#145) to a pty session's foreground process group (what ^C reaches) and to an exec-on-pipes command's own process group, for `HUP INT QUIT TERM KILL USR1 USR2 WINCH CONT STOP TSTP ALRM` (with or without `SIG`); another name is ignored, and only the control attachment of the connection that owns the channel can send one. Not delivered on Windows |
| Dial target | a URL | `wsh [user@]host` (dials `https://` then `wss://` on `--port`), or a full URL: `wsh wss://host:8443/rendezvous/ab12 command`, `ws://127.0.0.1:PORT/` | **CLI-only convenience**: a URL is dialled exactly as given (no transport fallback; `--port` and `--transport` do not apply). Plain `ws://` is accepted only to a loopback host |
| Host that runs in a browser page (`createMemoryHost`, `@johnhenry/wsh/reverse`) | yes, with injected `pty` / `fs` / `hostKey` | no (a Rust host is a process) | **JS-only**. A Rust *client* can operate such a host only with `dataStreams: false` (#132): the released Rust client over WebSocket cannot open QMux data streams, and says nothing in `Hello` that a host could use to decide. `wsh scp` works against such a host with the Rust client of the next `rust-v` release (it speaks `FileChunk`, #140); a released `rust-v0.11.0` or older `wsh scp` hangs against it (`wsh ls` and exec work) |
| Interactive shell UI | none -- this SDK is a protocol client, not a terminal emulator; pair with xterm.js/ghostty-web | `wsh connect`, `wsh sftp` (line-oriented REPL) | **Deliberately not unified** -- a browser embeds a terminal widget the host page owns; a CLI process owns its own TTY |
| Attach / resume | `attachSession()`, `resumeSession()`, `WshSession.seq` | `attach_session()`, `resume_session()` | **Wire-unified** (`Attach`/`Resume`/`Presence`); `seq` = cumulative output bytes. `@johnhenry/wsh/server` honours `last_seq` (bounded ring, gap errors) and answers Presence with `channel_id`/`seq`; the Rust `wsh-server` does the same (`rust-v0.2.0`+; fixed 256 KiB ring) |
| Reverse-connect / relay peer | `connectReverse()`, `trustRelayPeer()`; `@johnhenry/wsh/server`: `relay` option and `createReverseHost()` | `wsh reverse`, `wsh agent` (persistent, with startup-unit install) | **Wire-unified** (registration, discovery, signed peer records); **daemonization is CLI-only** -- a browser tab cannot be a background OS service. The Node relay is default-deny and bridges one operator per peer unless `maxOperatorsPerPeer` is raised (`busy:` reasons say so); E2E and bridged feature gates need `rust-v0.3.0`+ on the Rust side. **Several operators per peer (#93): both relays** (`maxOperatorsPerPeer`; `[relay] max_operators_per_peer`, default 1) **and both peers** (`createReverseHost({ maxOperators })`; `wsh --max-operators n reverse` / `agent run`, default 1), negotiated by `relay-multi-operator`; a Rust peer serving several operators does not seal bridges (see the reverse-mode notes), and the Rust relay leaves a peer connected when its operator leaves. The signed `KeyExchange` (`e2e-sign`) is carried by the Rust relay too |
| Post-quantum E2E (experimental) | `initiateE2E()` (WebCrypto ML-KEM-768 or `@noble/post-quantum` fallback) | `E2eKeyExchange` (`ml-kem` crate) | **Wire-unified** algorithm and transcript; key material backends differ by platform necessity |
| Unix-domain socket forwarding, both directions; named endpoints (#120) | `client.openUnix()`, `listenUnix()`, `forwardUnix()` (Node: `-L`/`-R` shapes with unix and TCP ends mixed), `openEndpoint()`; host: `gateway: { unix, endpoints }`, `createMemoryHost({ endpoints })` | `wsh-server` serves `OpenUnix`/`ListenUnix` (`[gateway] unix_connect`, `unix_listen`, `unix_replace_stale`, `unix_max_listeners`; same policy as the Node host); `wsh-client` has `open_tcp`/`open_unix`/`open_endpoint`/`listen_unix`/`listen_tcp`; CLI `wsh -L` / `-R` / `-N` with TCP, unix and `endpoint=NAME` ends, also through `--via` | **Wire-unified, both directions** (#145). A Rust host does not offer named endpoints (an in-page host does); the CLI reaches them. See [Forwarding with `wsh -L`](#forwarding-with-wsh--l---r---n) |
| Gateway flow control (#123) | credit per connection (`GatewayCredit`, feature `gateway-credit`); host caps for peers without it | `wsh-server` and `wsh-client`: 256 KiB per direction when both list `gateway-credit`; without it, per-connection and per-client byte caps (`max_buffered_bytes` 4 MiB, `max_client_buffered_bytes` 32 MiB) close the connection that exceeds them | **Wire-unified, negotiated**; an older peer on either side keeps working under the caps. `OpenUdp` flows are metered too (a datagram without credit is dropped) |
| TCP reverse tunnels (`ListenRequest`, #98) | `@johnhenry/wsh/server` `gateway.reverse` (off by default; loopback unless the operator lists addresses; port allow-list, nothing below 1024 unless named; bounded listeners/connections/backlog/idle); client `listenTcp(port, { onConnection })` | `wsh-server` `[gateway] enable_reverse_tunnels` + `reverse_bind_addr` (off by default, loopback, client `bind_addr` ignored); no port allow-list; no per-listener connection, backlog or idle bounds beyond `max_connections` | **Wire-unified** (`ListenRequest`/`ListenOk`/`ListenFail`/`InboundOpen`/`InboundAccept`; the JS host sends the real `peer_addr`/`peer_port`). **Rust still needs**: a port allow-list and per-client listener / per-listener connection / idle bounds to match the JS host. Accepted connections are metered by `gateway-credit` now |
| UDP (`OpenUdp`) as WebTransport datagrams (#124) | `client.openUdp()` over WebTransport when both ends list `gateway-datagram`: payloads are datagrams (4-byte flow id + payload), read from `maxDatagramSize`; oversize goes on the control stream (or drops); bounds: flows, packet and byte rates, idle; policy as TCP. Host: `gateway.udp`; Playwright test from Chromium | `wsh-server` serves `OpenUdp` over the reliable control stream only (one `GatewayData` per datagram); no datagrams, no rate bounds | **JS only for now** (negotiated by `gateway-datagram`, so a Rust peer keeps the reliable path). **Rust must implement**: list `gateway-datagram` in `ServerHello.features` on a WebTransport connection, accept/send datagrams `[gateway_id u32 BE][payload]` for `OpenUdp` flows when the client listed it (ignore the id of an unknown flow), read `maxDatagramSize` and send a bigger payload as `GatewayData` (or drop, by config), `connect()` the UDP socket to the checked address, and the same rate/flow bounds |
| Gateway destination policy by resolved address | `@johnhenry/wsh/server` `gateway`: resolved address checked, `allowPrivate` | fixed in the Rust release after `rust-v0.6.0`: a loopback/private/link-local/ULA/CGNAT/unspecified/multicast address is refused after resolution unless a rule names it, and the server connects to the address it checked | **Same rule on both sides** (a Rust server released before that still has the name-only check) |
| Operator proof to the peer, sealed bridge, signed initiator half (#117) | `reverseConnect(.., { sealed, requirePeerProof })`; host `createReverseHost({ requireOperatorProof })`; relay lists `operator-proof` | **Operator proof: yes.** The Rust relay lists `operator-proof` and carries `ReverseChallenge`/`ReverseProof`/`ReverseConnect.features`; `wsh reverse-connect` answers a challenge (`--operator-proof` / `--no-operator-proof`; by default only for a peer that registered the `operator-proof` capability, because a released Rust host cannot decode the field); `wsh reverse` / `wsh agent run` challenge, verify BEFORE accepting, and take `--require-operator-proof` and `--allow-operator`. **Sealed bridge and both signed `KeyExchange` halves: yes** (`wsh reverse-connect --sealed`; a host with an identity states `e2e` / `e2e-sign` / `e2e-sealed` in its `ReverseAccept` once it has proven the operator). The exchange is byte-identical to JS (transcripts compared against vectors printed by the JS code), hybrid X25519+ML-KEM-768 negotiated exactly as JS does, X25519 when the peer lists no ML-KEM key. A host started with `--require-operator-proof` REQUIRES the sealed bridge (the JS rule): until the key exists it hears and sends nothing but the key exchange, and drops a bridge that has not sealed in 10 s; an operator that does not seal gets no answer to its plain messages. Every message that would cross the relay travels as an `EncryptedFrame` on channel 0; a plain message (wrapped or not) is dropped; **a frame that does not open (tampered, replayed, reordered) closes the bridge** (stricter than the JS host, which drops the frame and ignores the rest). Not covered: a direct or pipe-relayed connection, and `GatewayData` outside a reverse bridge (#155) | **Wire-unified, negotiated** (`ReverseConnect.features`, `operator-proof`, `e2e-sealed`); both implementations seal a reverse bridge |
| Channel binding of the login signature (#119) | `requireChannelBinding` (client and server); kinds `host`, `cert-hash`, `tls-exporter` | Kind `host`: the client binds to the proven host key (`--require-channel-binding`, and it honours `channel-binding-required`), and `wsh-server` offers it and can require it (`[server] require_channel_binding`, needs `host_key`). `cert-hash` and `tls-exporter`: not in Rust (the Rust WebTransport client has no certificate-hash pinning; `ConnectConfig.cert_hash` binds it if a caller supplies one) | **Wire-unified, negotiated** (`channel-binding:<kind>` features); verified against the spec's test vectors |
| Pipe relay (#118) | `@johnhenry/wsh/pipe-relay` | operator side only (#145): `wsh --via wss://relay/r/<id> user@host command...` (also `connect`, `scp`, `ls`, `sftp`, `copy-id`), or the URL as the target. The host side of a pipe is not implemented in Rust. As on a direct connection the Rust client verifies the host-key proof (`host-key` / `host-key-sig` over its own nonce) before sending a credential, pins only a proven key, and binds the login to it (channel binding `host`; `test/rust/wsh-cli-identity.test.mjs`); the pipe-relayed session itself is not sealed (see Security model). `wsh -N -L` exits non-zero when the host drops the session (#156), and the error lines show the relay and a shortened id, never the whole rendezvous id | **Deliberately a relay without wsh parsing** -- nothing to unify on the wire. `--via` keeps `user@host` as the identity: its key is recorded in `known_hosts` under `host:port` (what a direct connection uses), never under the relay's address; a URL target is recorded under the URL's own authority, i.e. the relay's. The URL is not saved to `last_session.json` (the id is a capability) |
| Execution targets (#121): `Open.target`, `FileOp.target`, `OpenEndpoint.target`, `ListTargets` / `TargetList` | host: `targets` on `createWshServer` / `createMemoryHost` (own backends and `authorize(who, { target, kind })` per target, `requireTarget`); client: `openSession({ target })`, `exec(.., { target })`, `fileOperation(.., { target })`, `openEndpoint(.., { target })`, `listTargets()` | CLI: `wsh --target NAME [user@]host [command...]` and `wsh connect` (exec and shells only; every other subcommand, `-L`/`-R`/`-N` and `--share` refuse `--target`), `wsh targets [user@]host [--json]`; the client's `open_session(SessionOpts { target })` and `list_targets()` (file and endpoint calls send no target). **A Rust host with targets: not built**: `wsh-server` states no `targets`, refuses a request that names one and answers `ListTargets` with an error | **Wire-unified, negotiated** (`targets` feature; every new field optional, never sent to a host that did not advertise it) |
| Operator-side shared folders (`--share`, #159) | host side: `onShare(name, fs, who)` on `createMemoryHost` / `createWshServer` / `createReverseHost` (the host *uses* the operator's directories; `fs` is an object of async file operations, also shaped like an `fs` backend; `fs.root` is the operator's advisory, unverified path for the share, #164). The JS client does not offer shares | CLI side: `wsh --share NAME=/abs/dir[:ro\|:rw]` offers them, with each directory's path unless `--share-hide-path` (`wsh_client::share`, `wsh-cli`'s `sharefs`: descriptor-relative, never follows a link, see [Sharing a directory](#sharing-a-directory-with-the-host-wsh---share-159)); unix only. **A Rust host that uses shares: not built** (`wsh-server` does not state `shares`) | **Wire-unified, negotiated**: the host states the feature `shares`; the client sends one `ShareOffer` after login (opcodes `0xa8` `ShareOffer`, `0xa9` `ShareRequest`, host to client, `0xaa` `ShareReply`). No change notification, no sharing over `reverse-connect` |
| Sealed session: any authenticated connection incl. gateway/endpoint data (#155) | host `sealSession: 'offer' \| 'require'` (stage b); client `connect(url, { sealSession: false \| 'auto' \| true })` (stage c) | `wsh --sealed ...` (or automatic against `e2e-session-required`) seals a direct or pipe-relayed session; `wsh-server` offers or requires it on WebSocket (`[server] seal_session = "off" \| "offer" \| "require"`, needs `host_key`; `require` refuses WebTransport, WISP tunnels and password logins; no typed rpc channels while it is on) | **Wire-unified, negotiated** (`e2e-session`, `e2e-session-required`, `KeyExchange` for the connection's session id, `EncryptedFrame` channel 0) |
| Refusal event with stable reason codes (`onRefused`, #163) | `onRefused({ reason, who, detail })` on `createMemoryHost` / `createWshServer` / `createReverseHost`; `REFUSAL_REASONS` from `@johnhenry/wsh/host` | none: `wsh-server` and `wsh reverse` log a refusal, they have no callback (an embedding process has none) | **JS-only** -- a host-side callback of the embedding API, no wire change |
| `AuthOk.ttl` enforced, `token` opaque (#125) | `connectionTtlMs`; `client.authTtl` | `wsh-server` sends `ttl: 0` (no lifetime promised; `session_ttl` is the lifetime of a *detached* session) and an HMAC token that nothing accepts back | **Wire-compatible**: both fields are still sent (released peers require them). **Changed in the Rust server after `rust-v0.6.0`**: it used to send `session_ttl` (86400), which nothing enforced. The Rust client ignores `ttl` |
| `clientEnv` allow-list (#126) | default `TERM`, `COLORTERM`, `LANG`, `LANGUAGE`, `LC_*` | `wsh-server`: the same default; `[server] client_env = true` (everything, the old behaviour), `false` (nothing) or a list of names / `PREFIX*` (replaces the default) | **Both hosts**; wire unchanged. **Breaking default in the Rust server**, see the CHANGELOG |
| `authorized_keys` options (#122): `restrict`, `permit-*`, `no-pty`, `command=`, `max-sessions=` | `auth.authorizedKeys` lines with options on `createWshServer` / `createMemoryHost`; `parseAuthorizedKeyEntries()` | `wsh-server` reads `~/.wsh/authorized_keys` (then `~/.ssh/authorized_keys`) | **Same rules and the same vectors on both hosts** (`spec/key-options.vectors.json`, run by the JS suite and a Rust test); an option that is not understood keeps the key out, on both. See [Authorized-key options](#authorized-key-options-122) for the per-host column |
| Per-key capabilities and expiry (#122): `capabilities="..."`, `expires="..."`; `authorize()` may return a set | every entry the host has: `Open` kinds, `FileOp` read vs write, gateway TCP/UDP/unix/endpoint open and listen, MCP discovery and calls, targets, rpc channels, relay; refusals through `onRefused` (`not-permitted`, `key-expired`) | the same, except **no endpoints and no targets** (`endpoint:` / `target:` parse and grant nothing; such requests are refused); refusals are logged, there is no callback; no `authorize` | **Same grammar, same vectors, same refusal codes on both hosts**; default-deny only for a key whose line has `capabilities`. Neither covers sessions already open, see [Security model](#security-model) |
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

`wsh --version` and `wsh-server --version` print the workspace version the binary was built from (`wsh 0.15.0`), which is the
number in the `rust-vX.Y.Z` tag. Binaries of `rust-v0.9.0` to `rust-v0.10.0` printed a fixed `0.1.0`, so against one of those the
version cannot be read from the binary (look for a flag in `wsh --help` instead).

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

- **Execution targets: a name the client sends and the host decides on (#121).** Off unless `targets` is given. The host runs
  `authorize(who, { target, kind })` for every request that names a target (and `listTargets()`), and a refused target looks like an
  unknown one. It does NOT isolate targets from each other: a key allowed on two can use both, the library only routes and refuses, so the
  isolation a target gives is your backends'. `requireTarget` does not cover the gateway, MCP or `Attach`; without it a request with no
  target runs on the host's own backends, which any authenticated key can use, so a deployment that confines a key to one target must set
  `requireTarget` (or leave the host with no backends of its own). The Rust `wsh-server` has no targets and refuses any request that names one.
- **A key's `authorized_keys` options mean the same on both hosts, and a line that is not understood never grants anything (#122).**
  `restrict`, `permit-*`, `no-pty`, `command=` and `max-sessions=` are enforced at every entry the table in
  [Authorized-key options](#authorized-key-options-122) lists (`Open`, `FileOp`, the rpc channels, MCP, the relay entry
  points, installing a key), with the shared vectors run by both test suites. An option that is not understood -- or a value
  that is malformed, such as `max-sessions=0` -- keeps the key out altogether and is logged. They do NOT scope the gateway
  (TCP, DNS, unix, endpoints, reverse listeners) or the targets: a key that may not run commands can still use a gateway the host
  turned on, and `no-port-forwarding` is accepted and ignored. A key's permissions are read when the host starts (the Rust
  server) or when `createWshServer` is built (the Node host): editing the file does not change a running host. They limit what a
  key can ask for, not what a command it may run can do: `permit-exec` runs any command the client names (use `command=` to fix
  it), as the host's user.
- **Per-key capabilities and expiry narrow what a key may ask for; they are not a sandbox (#122).** `capabilities="..."` (and what
  `authorize` returns) is default-deny at the entry points in the [capability table](#capabilities-and-expiry-122-step-two), on both
  hosts, with the same vectors. What they do NOT protect against: (1) **what a granted capability can reach.** `exec` runs any
  command as the host's user, `fs:write` writes anywhere the `fs` root allows, `gateway:tcp:*:*` is an open proxy -- a capability is
  as strong as the backend behind it; the gateway's own policy (`allow`, resolved-address checks, unix paths) and the `fs` root still
  apply on top, and the capability only narrows. (2) **Things already open.** `expires` is checked at login and at every request; it
  does not close a connection, a running command, a forwarded stream or a reverse listener that was open when the key expired
  (use `connectionTtlMs` for that), and an `Attach` / `Resume` / `Signal` / `Resize` of a session the key already owns, session
  sharing, recordings and `Detach` are not gated by capabilities. (3) **Host names are compared as the client wrote them**:
  `gateway:tcp:db.internal:5432` constrains the name a client sends, not where a granted name resolves (the gateway's address
  policy does that). (4) **Password logins** are not narrowed (no key). (5) **Clock:** `expires` trusts the host's clock. (6) A key
  file is read when the host starts (Rust) or is built (Node): editing it does not change a running host. (7) The Rust server has no
  endpoints or targets: `endpoint:` and `target:` are accepted in a key line (so one file serves both hosts) and grant nothing there.
- **Several operators per peer share one peer, and the relay decides who is who (#93).** Off unless both the relay
  (`maxOperatorsPerPeer`, `[relay] max_operators_per_peer`) and the peer (`maxOperators`, `--max-operators`) are
  set above 1. The relay stamps each message with its own record of the sender's authenticated key and removes
  `to_fingerprint`; it checks the inner of a forward a peer wrote (size, decodes, a forwardable type) and drops what it
  cannot address. It does NOT protect operators from each other beyond that: they run as the same OS user as the
  peer, so a command one operator starts can read or kill another's files and processes. A Rust peer serving several
  operators cannot seal bridges (one seal per connection), so its bridges are as private as the relay is honest;
  use one operator per peer where that matters (`--require-operator-proof` needs it and is refused otherwise).

- **The Node gateway checks where a connection goes, not only what it was called.** `gateway.allow` matches the name a
  client sent, and then the address it resolves to must be globally routable (or permitted by `allowPrivate` or an
  IP-literal rule); the connection is made to that checked address, and `ResolveDns` answers are filtered the same way.
  Unix-domain sockets (`gateway.unix`) and named endpoints (`gateway.endpoints`) are off unless configured, are listed
  paths or names only, and sockets the host creates are `0600`.
- **TCP reverse tunnels (`gateway.reverse`) are off unless configured, bind where the operator says, and cap what they open.**
  A reverse listener is a port of the HOST that other machines can connect to, with the authenticated client on the other
  end of every connection. The host binds `reverse.bindAddr` (default `127.0.0.1`) and ignores the address the client
  asks for unless the operator listed it; ports come from an allow-list (default 0 and 1024-65535; privileged ports only
  if named); listeners per client, connections per listener, the listen backlog and idle time are bounded, and listeners
  die with the client's connection.
- **UDP flows are one destination, rate-limited in both directions.** An `OpenUdp` flow has the same destination and
  resolved-address policy as TCP, is `connect()`ed to the one address it passed (so no other source reaches the client
  through it), and is bounded by flows per client, packets per second per flow and per client, bytes per second per client
  and an idle timeout. The byte limit is the amplification bound: a small query to an open resolver or a UDP service
  that answers big (DNS, NTP, memcached-style services) can return no more than `bytesPerSecondPerClient` (4 MiB/s by
  default) to the client, and the same budget caps what the client can make the host send. Datagrams over a limit are
  dropped and counted (`server.gatewayStats()`).

**What is still yours:**

- **`wsh-mcp` runs as a client with your key (#127).** It reads a private key file you point it at (no passphrase support: protect the
  file, `0600`), logs in as you and hands the MCP client everything the host's `mcp` channel serves; whatever the MCP client (or the
  model behind it) asks of those tools is done as you. It does not pin the host unless you pass `--host-key` (it warns once on stderr),
  so a first connection to an unpinned host trusts whoever answers. After a reconnect it re-sends the client's `initialize` to a new
  server-side session: server state from the old session (subscriptions, per-session data) is not carried over. It does not filter
  or inspect MCP messages; a tool's own authorization is the host's (`mcp.authorize`).

- **What a reverse listener exposes.** Whoever can reach the bound port can talk to whatever the client behind it serves,
  as the client, with no authentication of their own: wsh authenticates the operator that asks for the listener, not the
  peers that connect to it. `bindAddr: '0.0.0.0'` (or an `allowBindAddrs` entry that does the same) puts that on every
  interface of the host, so firewall it and keep `ports` narrow. The client sees each peer's address (`InboundOpen`) and
  can reject it, but behind a NAT or proxy that address is not the real source. The Rust server's defaults are the
  same (loopback, off) but it has no port allow-list.
- **UDP is not authenticated or private beyond the tunnel.** `allow: ['*']` with a public resolver lets every authorized
  client send UDP to the internet from the host's address (a DNS-sized query, or a spoofed-looking flood limited only by
  the packet rates above); the bounds make that slow, not impossible, and an origin that answers many large datagrams
  to one small one is bounded by `bytesPerSecondPerClient`, not eliminated. WebTransport datagrams can be dropped,
  reordered and duplicated by the network, and are only as private as the QUIC connection that carries them (a
  datagram flow is not covered by E2E sealing, which is for sessions). A payload that did not fit a datagram travels on the
  reliable stream by default (see the README section above).

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
  **Update (#145): the Rust `wsh-server` now has an opt-in host key
  (`[server] host_key = "<path>"`, created 0600 on first start; see the
  capability matrix) and the Rust client verifies the proof; the paragraph
  below describes the state before that and still applies to a Rust server
  with no `host_key` configured, which proves nothing.**
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
- **The dev certificate from `--generate-cert` is a self-signed leaf** (not
  flagged as a CA, since #145), so a TLS client can trust it as a server
  certificate by being given the file (`SSL_CERT_FILE=~/.wsh/cert.pem`); it is
  still self-signed, so nothing vouches for it but that file. Before, it was
  flagged as a CA, TLS clients rejected it, and the only way in was
  `WSH_INSECURE_LOOPBACK_TLS=1`, which disables verification (loopback testing
  only).
- **Rust `wsh-server`: the client's environment is an allow-list, and `Signal`
  is delivered.** Only `TERM`, `COLORTERM`, `LANG`, `LANGUAGE` and `LC_*` of
  `Open.env` reach the command (at most 64 variables, bounded sizes);
  `[server] client_env = true` re-opens everything (a client can then set `PATH`
  or `LD_PRELOAD` for what the server runs, and the server warns at start-up).
  `Signal` goes only to the process group of a channel the sending connection
  controls. This does not make a command safe to run: an authorized key still
  runs commands as the server's user.
- **Forwarding (`wsh -L`/`-R`, `OpenUnix`, `ListenUnix`) lends the host's reach, not a sandbox.** Listing a socket in
  `unix_connect` gives every authorized key everything that socket's service can do: Docker's socket is root on the
  machine. The policy checks the path, not the peer, and cannot close the instant between the check and the connect
  (allow only directories no other local user can write to). It is not per key and has no rate limit beyond
  `max_connections`. `wsh -L` publishes a local port or socket to whoever can reach it: loopback by default, but an explicit
  `bind_addr` of `0.0.0.0` (the CLI warns) hands the forward to the network, and a local unix socket is `0600` only against
  other users, not against your own processes. A forwarded connection is as private as the wsh connection under it (a pipe
  relay sees it unless the legs are TLS). The Rust host binds a created socket inside a private `0700` directory and links it into place, so it is never visible with a looser mode and the process umask is not touched.
- **`wsh --share` hands a host a directory of YOUR machine, and the host is not trusted (#159).** What the host can do is
  exactly what the command line named: list and read everything under the directory (a read-only share still exposes every
  file in it, secrets included: share a directory made for the purpose, not `$HOME`), and with `:rw` change and delete all of it
  and fill the disk (the CLI bounds a file at 1 TiB and the read-plus-write rate, not the disk). What it cannot do is leave the
  directory: paths are resolved by descriptor with `O_NOFOLLOW` on every component (a link swapped in after a check is not
  followed), `..` is refused, a file with other hard links is never written, special files do not exist, a root that was
  replaced is refused (`ESTALE`), and nothing the host sends adds or widens a share. **Not covered:** a link that already
  exists inside the tree and points outside is simply not followed (so it appears broken to the host, but its name and target
  are listed); a local user who can write inside the shared tree is outside this model (they can race a rename, though never
  out of the root); the file *names and sizes* of everything under the share are visible to the host and to a relay that is not
  sealed (a share travels inside the session: a pipe relay sees it unless the legs are TLS and it is trusted, or the session
  is sealed, #155); a host that is itself malicious software on a page can read what the page's other code can ask for. The
  JS side treats the CLI as untrusted too (window, size, shape and deadline of every reply are checked), but an embedder
  that mounts `fs` is responsible for what it does with the files.
  **The root path (`ShareOffer.paths`, `fs.root`, #164) is a claim, not evidence.** By default the CLI tells the host where each
  shared directory is on your machine (so it can map a bind-mount source onto a share); the host cannot verify it, a modified
  client can send any string, and the CLI serves only the directory it opened whatever the path says. A host must use it to
  recognise a share, never to decide what is safe to mount or run. It reveals your directory layout (a user name, a project
  name) to the host and to a relay that is not sealed; `--share-hide-path` leaves it out.
- **Rust `wsh-server`'s `AuthOk.ttl` is 0 and its `token` is opaque** (as the
  JS host's, above): nothing is promised or enforced at connection level; do not
  treat the token as a credential.
- **`wsh --via` (pipe relay from the Rust CLI) is the operator side only, and
  not sealed unless you ask** (`wsh --sealed` seals a direct or pipe-relayed session, gateway
  data included, against a host that offers `e2e-session`: the JS host with `sealSession`, or
  `wsh-server` with `seal_session`; #155. Without `--sealed` the session is plain, and a relay reads
  it). The Rust client now verifies the host-key proof
  (`host-key` / `host-key-sig` over its own `host-key-nonce`) before sending
  any credential, records only a PROVEN key in `known_hosts`, binds the login
  signature to that key (channel binding `host`), and refuses a changed key
  always. A replayed `ServerHello` or an impostor's key is refused as the JS
  client refuses it. What is still unprotected without `--sealed`: the session is not sealed
  end to end, so the relay sees
  session traffic in the clear unless the legs are TLS and it is trusted not
  to read them (it terminates each leg's TLS), and it can stamp an identity on
  a plain message after the handshake. A host with no host key proves nothing:
  the CLI connects to it (as every release did) unless `--require-host-key`
  says otherwise.

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
