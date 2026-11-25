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
- [wsh and browsermesh](#wsh-and-browsermesh)
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

**Login names (`usernamePattern`).** A host admits only names of an OS account's shape, `^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`, because a name reaches
`exec` environments, file paths and logs. A host that does not map names to accounts (a page, or a mesh peer named by a base64url identity
hash, which may start with a digit or `-`) says what it admits: `createWshServer({ usernamePattern: /^[A-Za-z0-9_-]{1,64}$/ })`, also on
`createMemoryHost` and `createConnectionFactory`. Off unless given. **Not loosened by any pattern:** a name is 1 to 256 characters with no control
character, no `/` or `\`, and is not `.` or `..`, and a pattern that matches the empty name is refused at start. The pattern is the embedder's
decision: whatever `exec`, `fs` or `authorize` do with the name is theirs to keep safe, and a wider pattern widens what they must handle
(`createReverseHost` and the Rust `wsh-server` keep the default shape).

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

Two more options give a key a finer, **default-deny** licence. Nothing changes for a key line that has neither. The notation is written
as a specification in [`spec/capabilities.md`](spec/capabilities.md) (see [Identity and capabilities for other implementations](#identity-and-capabilities-for-other-implementations-220)).

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
| `objects:<root>` , `objects:<root>:<op>` | on that root of `wsh-objects` (`*`: every root), every operation, or just `get`, `call`, `set` or `on` (events) (#190) | JS host only: a `wsh-objects` handler of `exposeObjects` / `createPageHost({ expose })`. The Rust server has none, and it refuses a key line that holds an `objects:` capability (an unknown capability fails closed) |
| `relay` | register, list and connect through the relay | `ReverseRegister` `ReverseList` `ReverseConnect` / the same |

`<host>` is a name, an IP literal (IPv6 in brackets), `*`, or `*.suffix` (any subdomain, not the apex; the name is compared
case-insensitively as the client sent it, so resolution is the gateway's `allow` policy's business). `<port>` is a number or `*`.
`<path>` is absolute with no `.` or `..`, exact or ending in `/*` (anything below that directory). `<name>`/`<tool>` are exact or `*`.
`objects:<root>[:<op>]` follows the roots a host named in `exposeObjects`: a key that holds none keeps what `rpc:wsh-objects` gives (every root, every operation the host's
allow-lists let through); a key that holds any is **limited to the roots and operations they name** (`objects:window:get` reads `window` and nothing else; `objects:store` is every
operation on `store`; `objects:*:get` reads every root), may open the channel without `rpc:wsh-objects`, is not told of the roots it cannot use, and still meets the host's
allow-lists (a capability narrows them and never widens them). Walking to a path (reading the properties on the way) counts as part of any operation on that root. The key
is asked afresh for every operation, so an `expires` holds at call time.
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

#### Identity and capabilities for other implementations (#220)

The notation above is written down once, as a specification, with vectors that another implementation can run:

- **`spec/capabilities.md`** is the grammar of one capability, what each wildcard matches (and what it does not: `*.example.com`
  is not `example.com` and not `evilexample.com`; `/srv/*` is not `/srv`), what each request kind needs, the order of the checks
  (expiry, the options, the list), and what an implementation does with an entry it does not understand: **fail closed**, the whole
  list permits nothing and a key line that holds it is refused.
- **`spec/capabilities.vectors.json`** (with a `version`, and `spec/key-options.vectors.json` for the option syntax) is "does a
  holder of list L permit request R" as data. The JS evaluation and the Rust `wsh-server` both run it. A case names the host classes
  it applies to: the Rust server has no named endpoints, no targets and no `wsh-objects`, and **states that subset by refusing**:
  a key line with an `objects:` capability is refused at load there (`unknown-capability`), rather than accepted and ignored, so a
  key meant for a page cannot sit unnoticed on a machine that cannot honour it. Both files ship in the npm package:
  `import vectors from '@johnhenry/wsh/spec/capabilities.vectors.json' with { type: 'json' }`.
- **`@johnhenry/wsh/capabilities`** exports the evaluation: `permits(capabilities, request, { expires, now })` is a boolean,
  `checkCapabilities(...)` the refusal (`{ code, capability }`) when not. It is pure, browser-safe and fails closed (no list, an
  entry it does not know, or a request kind it does not know permits nothing).
- **`@johnhenry/wsh/identity`** is one stable module for a key's names: the raw 32-byte key, the OpenSSH `ssh-ed25519` line
  (`rawKeyToOpenSsh`, `openSshToRawKey`, `publicKeyToOpenSsh`), the hex **fingerprint** (SHA-256 of the raw key) and the base64url
  **pod id** (the same 32 bytes: `fingerprintToPodId`, `podIdToFingerprint`), `identityOf(key)` for all four, and
  `authorizedKeyLine(key, { capabilities, expires, comment })`, which builds a line for an `authorized_keys` file and **refuses
  unsafe input**: no `capabilities` unless you say `allowFullAccess: true` out loud (a line with none may do everything), only
  capabilities the notation knows, a timestamp it can read, no control character or line break in the comment, a plain Ed25519
  key, and it reads its own line back through a host's parser before returning it.
- **The gateway error table** is data too: `GATEWAY_FAIL`, `GATEWAY_FAIL_TABLE` and `gatewayFailName(code)` are exported from the
  package root (`@johnhenry/browsermesh-netway` decodes the same numbers; the vectors are `spec/gateway-fail.vectors.json`). `5` is
  `GATEWAY_DISABLED` (the spec and the Rust server) and `TIMEOUT` is `8` (#223). A Node gateway of 0.51.0 or earlier sent `5` for a timeout,
  so a reader keeps treating a `5` as "the gateway is disabled, or a timeout from an older Node gateway": `GATEWAY_FAIL_TABLE` and the
  message of a `GatewayError` that carries `5` say both. A new Node gateway sends `8` for a timeout, so a client written for the
  old number (`code === 5` meaning a timeout) must also accept `8`.
- **For the object and MCP layers**: the identity handed to `authorize(who, op)` is `{ username, fingerprint, podId? }`.
  `fingerprint` is always the hex hash of the caller's key; `podId` is there when the transport knows the caller by one. A
  transport that is not wsh gives an identity object (`createDuplexPeer({ send, who: { podId } })`, or `attach(peer, { who })`)
  instead of putting a pod id in a field named `fingerprint`; whichever of the two it gives, the other is derived, and an identity
  that names two different keys is refused. A wsh caller keeps the `{ username, fingerprint }` it always had. The transport's own
  grants are `createDuplexPeer({ permit })`, asked per operation (`get`, `call`, `set`, `on`, and `walk`); `permit` answering anything
  but `true`, or throwing, refuses.

What none of this is: `permits()` decides what a list says; it does not authenticate the holder, and a list is only as portable as
the oldest implementation that reads it (a newer notation's entries fail closed on an older reader). `authorizedKeyLine` writes a
grant; whoever may install it into a file a host reads is who decides, and a browser-stored key that is valid on real machines is
a decision to make deliberately (see [wsh and browsermesh](#wsh-and-browsermesh)).

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
# TCP reverse tunnels (`enable_reverse_tunnels = true`) and UDP flows: the Node host's bounds and defaults
reverse_ports = [0, "1024-65535"]    # ports a client may ask for; a list REPLACES this default, so below 1024 only when named
reverse_max_listeners = 4            # per client connection
reverse_max_connections_per_listener = 16
reverse_backlog = 8                  # listen(2) backlog
reverse_idle_secs = 300              # an accepted connection quiet for this long is closed; 0 = never
udp_max_flows = 16                   # per client connection
udp_packets_per_second_per_flow = 500
udp_packets_per_second_per_client = 2000
udp_bytes_per_second_per_client = 4194304   # both directions; the amplification bound. 0 on any rate = no limit
udp_idle_secs = 60                   # no datagram in either direction for this long closes the flow (at least 1)
udp_datagrams = true                 # offer `gateway-datagram` on WebTransport: a client that lists it too gets UDP payloads as datagrams; false = control stream only
udp_oversize = "reliable"            # a payload over one datagram: "reliable" (control stream, ordered, retransmitted) or "drop"
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
  bridge) and `stream-announce` is not offered; rpc is stated as `rpc-virtual` instead of `rpc` (see
  [RPC channels](#rpc-channels-object-mode)). It is an option rather than a negotiation because no released
  client says whether it can open streams: the Rust client's `Hello` carries only `mcp` and `file-transfer`. The JS client works
  either way. `host.accept(socket, { dataStreams })` overrides it per connection.

**Serving a socket you opened yourself:** `host.accept(new WebSocket(url))` works on a socket that is still connecting (the
host's first bytes are held until it opens). `accept()` of an in-page host through a relay or a byte pipe is what the
[browser suite](#browser-tests-and-bundle-size) runs against the released Rust CLI.

**`rpc`** takes handler functions only, `rpc: { calc: (channel, ctx) => channel.onRequest('add', ({ a, b }) => a + b) }`
(the `RpcChannel` is the one `@johnhenry/wsh/server` hands its handlers), with `rpcMaxMessageBytes` (default 1 MiB) and
`rpcMaxInflight` (default 64). Clients use `client.openRpc('calc')` unchanged. `createReverseHost({ rpc, rpcMaxMessageBytes,
rpcMaxInflight })` takes the same option, so a host behind a relay can offer rpc (it needs `reportFeatures`, the default).

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
| `@johnhenry/wsh/testing` | the QMux record and frame codec (`encodeStream`, `encodeRecord`, `RecordDecoder`, `decodeFrames`, the varint and the other frame encoders), for a test that reads, alters and re-wraps what travels on a connection; and two test doubles for code that embeds wsh: `createInProcessPipeRelay({ tap })` (the real pipe relay in this process, with a `WebSocket` that dials it, a record of every message it copied, and a `tap` that may change, drop, repeat or add to what it writes, like a hostile relay) and `createMemoryPair({ host, username })` (a memory host and a client already logged in to it). **Experimental: not part of the stable API**; it may change or disappear in any release. Importing only the codec costs under 1 kB: the doubles are separate exports a bundler drops |
| `@johnhenry/wsh/identity` | a key in its four spellings, and `authorized_keys` lines: `fingerprint` and `podId` of a raw key, `fingerprintToPodId` / `podIdToFingerprint`, `rawKeyToOpenSsh` / `openSshToRawKey` / `parseOpenSshKey` / `publicKeyToOpenSsh`, `identityOf`, `normalizeIdentity`, `authorizedKeyLine`. Stable; see [Identity and capabilities for other implementations](#identity-and-capabilities-for-other-implementations-220) |
| `@johnhenry/wsh/duplex` | a full wsh session over a duplex of messages another library provides: `serveWshOverDuplex(host, { send })`, `connectWshOverDuplex({ send }, credentials)`, `createDuplexSocket`. Sealed by default; see [wsh over a duplex](#wsh-over-a-duplex-220) |
| `@johnhenry/wsh/objects-types` | `describeRootTypes(description, { name })`: the `.d.ts` text for a root of `wsh-objects`, from what a key may do (a pure function), and `checkTypeText`; see [Typed remotes](#typed-remotes-219) |
| `@johnhenry/wsh/capabilities` | `permits(capabilities, request)`: the notation of key capabilities as a pure function, the one `@johnhenry/wsh/server` and the memory host evaluate. Stable; same section |
| `@johnhenry/wsh/spec/*.json`, `*.md`, `wsh-v1.yaml` | the data files of the specification: `capabilities.md`, `capabilities.vectors.json`, `key-options.vectors.json`, the wire spec |
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
| `@johnhenry/wsh` (whole entry point) | 165.8 kB | 50.3 kB |
| `@johnhenry/wsh/memory` (whole entry point) | 233.4 kB | 72.9 kB |
| `@johnhenry/wsh/host` (whole entry point) | 127.9 kB | 42.1 kB |
| `@johnhenry/wsh/reverse` (whole entry point) | 221.7 kB | 68.6 kB |
| `@johnhenry/wsh/pipe-relay` (whole entry point) | 7.0 kB | 3.0 kB |
| `@johnhenry/wsh/testing` (whole entry point) | 241.2 kB | 76.0 kB |
| `@johnhenry/wsh/page` (whole entry point) | 327.0 kB | 104.1 kB |
| `@johnhenry/wsh/objects` (whole entry point) | 201.5 kB | 62.0 kB |
| `@johnhenry/wsh/objects-types` (whole entry point) | 10.2 kB | 4.2 kB |
| `@johnhenry/wsh/capabilities` (whole entry point) | 10.6 kB | 3.8 kB |
| `@johnhenry/wsh/identity` (whole entry point) | 15.7 kB | 5.7 kB |
| `@johnhenry/wsh/duplex` (whole entry point) | 140.1 kB | 42.4 kB |
| `import { encodeRecord } from '@johnhenry/wsh/testing'` | 1.8 kB | 0.9 kB |
| `import { generateKeyPair } from '@johnhenry/wsh'` | 0.4 kB | 0.3 kB |
| `import { WshClient } from '@johnhenry/wsh'` | 135.9 kB | 40.8 kB |
| `import { createConnectionFactory } from '@johnhenry/wsh/host'` | 104.6 kB | 34.2 kB |
<!-- bundle-size:end -->

### Signing with a page-held signer

`connect()`, `WshClient.exec()` and `connectReverse()` take `signer: { publicKey, sign(data) }` instead of `keyPair`
(not both): `publicKey` is the raw 32-byte Ed25519 key or a public `CryptoKey`, `sign` returns the 64-byte signature
(sync or async). For keys that live in a wallet, a hardware token or another realm and are not a `CryptoKeyPair`.

### A page as a host: `@johnhenry/wsh/page` (#190)

A page cannot listen, but it can dial a [pipe relay](#a-pipe-relay-johnhenrywshpipe-relay-118) it chose and be a wsh host behind it.
`createPageHost` does that for **the tools the page has registered with [WebMCP](https://webmachinelearning.github.io/webmcp/)**: the
page author has already chosen a small surface, named it, given each tool a schema and said which ones change things, and the bridge
carries exactly that to an MCP client (`wsh-mcp --sealed`, or `client.openRpc('mcp')` with `mcpClientTransport`). It is key login only,
sealed sessions only, and there is no anonymous mode, no password login, no exec and no file access.

```js
import { captureWebMcp, createPageHost } from '@johnhenry/wsh/page';

captureWebMcp(window);          // FIRST, before the application's code registers a tool (see "Three sources" below)

const host = await createPageHost({
  window,                       // required, and the only realm this touches: nothing is reached for on the global
  relay: 'wss://relay.example/pipe',
  name: 'shop-tab',
  authorizedKeys: [operatorKeyLine],   // required; `authorized_keys` lines, options apply (see "Per-key narrowing")
  mcp: {
    allow: ['search_products', 'add_to_cart'],   // by tool name; nothing is allowed by default
    approve: 'consequential',                    // 'never' | 'consequential' (default) | 'always'
  },
  onSession(who) {},            // a key logged in; return false to refuse it (ask the person first)
  onRefused(r) {},              // as for every host (REFUSAL_REASONS)
});

host.operatorUrl;   // give this to the operator: the rendezvous id in it pairs the operator with this page
host.fingerprint;   // this page's host key: the operator pins it (client option `expectHostKey`, `wsh-mcp --host-key`)
host.sessions;      // who is connected now
await host.revoke(fingerprint);   // end that key's session and refuse it until the host is closed
await host.close();
```

On the far side nothing new is needed: `wsh-mcp --sealed --host-key <host.fingerprint> --identity KEY <host.operatorUrl>` is a stdio MCP
server any MCP client can launch, and in code `client.connect(host.operatorUrl, { keyPair, sealSession: true })` then
`client.openRpc('mcp')`. The host serves one operator at a time and dials the relay again when a session ends.

**The dial-out form (`connect`, #219), off unless written.** For an operator that *listens* (a process of yours that accepts connections), the page can dial it itself
instead of waiting behind a relay: `createPageHost({ window, connect: 'wss://operator.example/pages/shop', name, authorizedKeys, mcp, expose })` (not together with `relay`;
there is no `operatorUrl` and no rendezvous id, both are `null`). The URL is dialled **exactly as written** (no role or rendezvous id is added), must be `ws://` or `wss://` with
no user name, password or fragment in it, and is **never logged** (its query may hold a secret). Everything after the socket opens is what it is behind a relay: key login only
(`authorizedKeys`), a sealed session, `onSession`, the person's approval for consequential tools, the visible indicator and **Stop** (which also refuses that key), the
`mcp` and `wsh-objects` channels, closing when the window leaves its origin, and dialling again after a session or a failed attempt (`reconnect`, with the same backoff). The operator
is the wsh *client* on what it accepts, for example in Node:

```js
import { WebSocketServer } from 'ws';
import { connectWshOverDuplex } from '@johnhenry/wsh/duplex';

new WebSocketServer({ port: 9000 }).on('connection', (ws) => {
  const link = connectWshOverDuplex({ send: (bytes) => ws.send(bytes), close: () => ws.close(1000) },
    { username: 'alice', keyPair, expectHostKey: pageHostFingerprint });   // the page shows host.fingerprint; the login is sealed and bound to it
  ws.on('message', (data) => link.receive(data));
  ws.on('close', () => link.end('the page left'));
  link.connected.then((client) => client.openRpc('mcp'));
});
```

What the form changes: **nothing sits between the page and the operator**, so there is no relay to see ciphertext (the sealed session still hides the traffic from a hop you did not
choose, such as a proxy), and **the page chooses whom to dial**: whoever answers at that URL learns the page's host key and what its handshake states before any key logs in, and can
only try to log in (a key that is not in `authorizedKeys`, or whose `capabilities` do not allow it, gets nothing). What it does **not** protect against: a URL that points at the wrong
listener is not noticed by the page (the operator must pin the page's host key, and the page does not pin the operator: it authenticates keys, not endpoints); a page that
is told to dial by code you did not write dials; the page redials the URL for as long as the host is open, so a listener that wants a quiet period must say no at login, or the host be
closed. Browser pages can dial `wss://` endpoints their content security policy allows (`connect-src`), and not `ws://` from an `https:` page.

**`window` is explicit.** `createPageHost`, `webmcpTools` and `captureWebMcp` read nothing but the object they are given: where tools are
registered (`window.document.modelContext`, the older `window.navigator.modelContext`), where the indicator is drawn
(`window.document`), which `WebSocket` dials the relay, and whose origin is reported. A test greps the entry point's source for
`globalThis`, `document`, `navigator`, timers and so on. So the same code serves an iframe's `contentWindow`, a popup, a worker's `self`
(no document: supply `indicator` callbacks and a `prompt`, or say `unattended: true`), or a fake window in a test. **Passing `window` is not
exposing it**: nothing of the page's object graph is reachable unless `expose` is written as well (see [Remote objects](#remote-objects-johnhenrywshobjects-190)). One window per host; serving two is two hosts with two names. The host
**never follows a navigation to another origin**: when `window.location.origin` changes (or cannot be read, as for a frame that went
cross-origin) or the window closes, it tells the operator why, ends the sessions and closes (`host.closedReason`, `onClose`). It checks on
`pagehide`, every second, and before every call. A host that runs in another realm than the window it serves (an opener serving a
popup, a parent serving an iframe) passes that realm's `timers: { setTimeout, clearTimeout, setInterval, clearInterval }`: the window's own timers die with its document.

**Three sources of tools** (the draft API has changed more than once, so none is relied on alone; they are merged by name, earlier wins):

1. an explicit list, `mcp: { tools: [...] }`: the same definitions the page passes to `registerTool`. The most robust, and the form to
   use when the page controls its own code;
2. the capture shim, `captureWebMcp(window)`, called before the application's code: it wraps `registerTool` on
   `document.modelContext` (the current draft) and `navigator.modelContext` (the older one; also `provideContext`, `unregisterTool`,
   `clearContext`), forgets a tool when its abort signal fires or `unregister()` is called, and where the browser has **no** `modelContext`
   provides a minimal one (registration in either generation's style, `getTools`, `executeTool`) so the application code runs everywhere;
3. the browser's own API, where it lets a page read its tools: `document.modelContext.getTools()` and `executeTool()` (both are in the
   current draft; feature-detected, and listed only for the served window), plus its `toolchange` event for `tools/list_changed`. Absent in most
   browsers today, so this path is exercised against a fake `modelContext` only.

**The mapping to MCP.** `tools/list` states `name`, `title`, `description`, `inputSchema` and `outputSchema` as registered and the
annotations: `readOnlyHint` stays, `consequentialHint` is `destructiveHint`, and what MCP has no field for (`untrustedContentHint`,
`consequentialHint`, `debugging`, and whether the bridge treated the tool as consequential) is in `_meta["webmcp/annotations"]`.
`tools/call` runs `execute(input, { signal })`; an MCP cancel (or the session ending, or `callTimeoutMs`) aborts the signal. An object result is
`structuredContent` with its JSON as the text rendering (a result already shaped `{ content: [...] }`, as the draft's examples return, is kept); a thrown
error or a rejected promise is a result with `isError` and **the message only, never a stack**; every result carries `_meta["wsh/untrusted"]`
and `initialize` says the results are untrusted. A tool registered or unregistered later is `notifications/tools/list_changed` (only for
tools the session may see). A tool that is not allowed, not permitted to the key, or not there answers the same way (`unknown tool`).

**Bounds, each refused by name** (`mcp.limits`): `maxTools` 64 (more are not listed), `maxSchemaBytes` 16384 per tool (a tool over it is not listed
or callable), `maxInputBytes` 65536, `maxResultBytes` 262144, `maxInflight` 4 per session, `maxCallsPerMinute` 30 per session (an unknown tool name counts),
`callTimeoutMs` 120000. The error names the bound (`refused: maxInflight: more than 2 calls in flight`); `onCall` hears of every one.

**Asking the person.** `approve: 'consequential'` (the default) asks before a tool that is **not marked `readOnlyHint`** runs (anything not
marked read-only is consequential; `consequentialHint` forces it), `'always'` before every call, `'never'` not at all. The question is `mcp.prompt(call, who, { signal })`
(true allows; anything else, a throw included, denies); the default, where the window has a document, is an accessible modal dialog that names the tool and
the caller's key fingerprint, shows the input **as text** (nothing is parsed as markup), puts focus on Deny, keeps Tab inside it, treats Escape as Deny,
returns focus afterwards and denies after 60 seconds. Questions are asked one at a time. Deny is an MCP error and the tool does not run.

**Over any duplex, not only a wsh channel (#220).** `webmcpTools(...)` is a handler written for a channel; `serveMcpOverDuplex(handler,
{ send, who, permits })` (also from `@johnhenry/wsh/page`) gives it one made of two functions you already have, so a transport that is not
wsh at all (a mesh channel, a `MessagePort`) can carry the same tools: feed what arrives to `session.receive(message)`, `send` what goes out,
`session.close(reason)` when the link ends. **The far side speaks plain MCP**: JSON-RPC 2.0 messages as objects (`{ jsonrpc: '2.0', id, method, params }`
and the matching result or error, notifications with no `id`; no batches), so an MCP SDK `Client` connects through any `Transport` that moves them.
The handler's bounds, `approve` and `prompt`, `onCall` and the untrusted labelling are unchanged. The seam adds `maxMessageBytes` (default 1 MiB,
either direction), `maxInflight` (default 64 requests of any kind), one answer per id, and refuses a message that is not JSON-RPC 2.0. `who` is
`{ username, fingerprint, podId }` (what the prompt and `onCall` see), and `permits` is asked per tool, so `(req) => permits(caps,
req)` of `@johnhenry/wsh/capabilities` narrows it by `mcp:TOOL`. **It authenticates and seals nothing**: who is on the other end, and what they
were granted, are the transport's to establish; they are not in the messages.

**The indicator.** While a session is connected, `window.document` has a visible element (`data-wsh-page="indicator"`, `role="status"`) saying so,
with the key's fingerprint and a **Stop** button that calls `revoke`. Stop ends the session (the operator is told why), and that key is refused until the host
is closed: a Stop that lets the same key straight back in is not a Stop. If something in the page removes the element while a session is connected it is put back. `indicator: false` is
refused unless `unattended: true`; a window with no document refuses to start unless the embedder supplies `indicator: { connected(who, { stop }), disconnected(who) }` or
`unattended: true`; an unattended host denies what needs approval unless `mcp.prompt` answers.

**Per-key narrowing.** Put `capabilities="mcp:search_products"` in the key's `authorized_keys` options and that key lists and calls only that tool: the intersection
with `mcp.allow`. A key whose capabilities name no `mcp:` tool cannot open the channel. For this the host tells every rpc handler what the key may do: `ctx.capabilities`
(the list, or `null`) and `ctx.permits({ kind: 'mcp-tool', tool })` (asked afresh each time, so `expires` holds). A handler that narrows by `permits` itself declares
`handler.capabilityScoped = true`; only then may a key that names tools but not `mcp:*` open the `mcp` channel (every other `mcp` handler still needs `mcp:*`).

**The host key.** Unless you pass `hostKey` (a key pair or a signer), each page load generates a fresh non-extractable key: the page can sign with it but nothing can read
it, and it dies with the load. So an operator can pin `host.fingerprint` for that load (show it in the page, or hand it over with `operatorUrl`), but a `known_hosts` entry from an
earlier load will not match and trust-on-first-use gives no continuity. To keep one identity across loads, inject a store: `hostKeyStore: { load(), save(pair) }` (a non-extractable
`CryptoKeyPair` can be kept in IndexedDB).

**What this narrows, and what it cannot make safe.**

- It narrows *who* may call *which* tool: a key login, a sealed session (the relay sees metadata and ciphertext, not a tool name or an argument, and cannot inject a call),
  an allow-list by name, the key's capabilities, the person's approval for consequential tools, bounds on every dimension, and a visible Stop.
- **A tool does whatever its `execute` does, with the user's session.** A tool that places an order, reads the account page or calls an API as the user does that for the remote
  caller; the allow-list and the dialog decide whether it may be asked, not what it does. Register tools you would be willing to hand to the key's holder, and mark every tool
  that only reads `readOnlyHint: true` (a mislabelled tool skips the question).
- **Results are the page's data and may carry text written by third parties** (a product review, a message). They are labelled untrusted and `initialize` says so, but an MCP
  client or its model has to treat them as data, not instructions: that is the client's job, not the bridge's.
- **The approval dialog is the page's own.** A page script (or a tool) can remove, cover or click it; the indicator is put back, not guarded. The bridge protects the person from a remote
  caller, not from code already running in the page.
- A host that is left open (`reconnect`, the default) can be reached by anyone who holds the rendezvous id **and** an authorized key; the id is a secret, not a credential.
- What is not offered: exec, files, gateway, more than one operator at a time, and (unless `expose` is written) any access to the page's objects. With `expose`, what that adds is stated in
  [Remote objects](#remote-objects-johnhenrywshobjects-190); `createPageHost({ expose })` then also serves the `wsh-objects` channel, under its own capability (`rpc:wsh-objects`),
  with the same sealing, indicator, Stop and window guard.

### Remote objects: `@johnhenry/wsh/objects` (#190)

`wsh-objects` is an rpc protocol that reaches an object graph by path: a page's `window`, a worker's `self`, any object a host names as a **root**. It is `values` mode:
only plain cloneable values ever cross (on a root that has not opted in to [handles](#handles) there are no handles and no callbacks; events are delivered as copies, see below).
Nothing is reachable but the named roots, and nothing in them is allowed until an allow-list says so.

```js
// the host: any host that takes `rpc` (a Node server, a memory host, a reverse host, a page host)
import { exposeObjects } from '@johnhenry/wsh/objects';
createMemoryHost({ auth, hostKey: true, dataStreams: false, sealSession: 'require', rpc: {
  'wsh-objects': exposeObjects({
    roots: { window },                                          // named roots: all that is reachable
    mode: 'values',
    allow: {                                                    // by operation, as paths from a root; `*` is one segment, `**` any number
      get:  ['window.document.title', 'window.location.href', 'window.app.**'],
      call: ['window.app.**'],                                  // covers construct
      set:  ['window.app.settings.theme'],
    },
    authorize(who, op) { return true; },                        // asked for each operation the allow-list let through: { kind, root, path, text }
    limits: { maxOps: 32, maxValueBytes: 262144 },
  }) } });

// the far side (importing the entry point also adds client.openObjects())
import { get, set, call, construct, snapshot, describe } from '@johnhenry/wsh/objects';
const { window: win } = await client.openObjects();            // the roots, as lazy references
await win.document.title;                                       // a reference is a lazy path: this one `await` sends ONE `resolve` request,
await win.app.cart.items.length;                                // whatever the length of the chain, calls included
await win.app.cart.add({ sku: 'A1', qty: 2 });                  // a call with plain-data arguments; `this` is the object the method was found on
await set(win.document, 'title', 'Paid');                       // not `=`: an assignment cannot be awaited or report a refusal, so it throws a sentence naming set()
await snapshot(win.app.state, { depth: 3, maxBytes: 256_000 }); // a bounded deep copy (subtrees past `depth` are null)
await describe(win.app);                                        // names and types the allow-list could walk to, for a REPL or completion
await get(win.app, 'then');                                     // a remote property really named "then" (`ref.then` is the awaiting function)
```

`createPageHost({ ..., expose: { window: { mode: 'values', allow: { get: ['document.title', 'app.**'], call: ['app.**'] } } } })` is the same thing on a page host (paths relative to the
root, which is the `window` that was passed; another root needs `{ object }`), with the sealing, the indicator and Stop, the window guard and the key capability `rpc:wsh-objects`.
The wire is `roots`, `resolve { root, ops: [{ get } | { call, args } | { construct, args }] }`, `set { root, path, value }`, `describe`, `snapshot { root, path, depth, maxBytes }` (a notification
`closing { reason }` precedes a host's ending of a session); a value is `{ v }`, or `{ u: kind, type?, text? }` for what cannot be cloned. The core (`objects-core.mjs`: paths,
serialisation, limits, allow-lists) knows nothing of wsh and needs only a duplex seam (`createDuplexPeer({ send })` is one over a bare `send` / `receive`; an `RpcChannel` is another);
one test suite runs over both.

**What crosses.** A result is plain data (null, booleans, numbers, strings, bytes as `Uint8Array`, arrays, plain objects; bounded in depth and bytes) or a **named non-value**: a
function, a symbol, a bigint, a `Date`, a `RegExp`, an `Error`, a DOM node or any other object arrives as a `NonValue` (`{ kind, type?, text? }`, e.g. `{ kind: 'object', type: 'HTMLDivElement' }`), **never as a
handle**. Inside an object or array a member that cannot be cloned is left out (`null` in an array), as JSON does; the keys `__proto__`, `constructor` and `prototype` are never copied; a circular
reference is left out; an integer past 2^63 is named (it does not survive the integer encoding). What is sent *to* the host is plain data too, copied, and refused if an object has a prototype of its own or
a refused key. A function, or a remote reference (a path, not a value), cannot be passed as an argument.

**Always refused, in every list:** the path segments `__proto__`, `prototype`, `constructor`, `__defineGetter__`, `__defineSetter__`, `__lookupGetter__`, `__lookupSetter__`; `eval`, `Function`, `import`,
`execScript`; `call`, `apply` and `bind` of a function (they re-aim it); `setTimeout`, `setInterval` and `setImmediate` with a string. An allow-list entry that names one is a configuration error.
**Refused until an entry names them** (a wildcard such as `window.**` does not): `document.cookie`, `localStorage`, `sessionStorage`, `indexedDB`, `navigator.credentials`, `fetch`, `XMLHttpRequest`,
`postMessage`, `open` (as a path segment anywhere, so an application method called `open` needs its own entry). **Per-operation allow-lists by path glob; nothing is allowed by default**, and with no `call`
and no `set` entries the access is read-only for real. To walk to an allowed path a session may read the properties on the way (`window.app` toward `window.app.cart.items`) and no others; after a call the
chain goes on the *result*, whose path is the callee with `()` (`window.app.getCart().items`). The order of checks is: the always-refused names, the allow-list, the entries that must name a path,
`authorize(who, op)`, then the operation.

**Bounds, each refused by name** (`limits`): `maxOps` 32 per request, `maxArgs` 16, `maxDepth` 8, `maxValueBytes` 262144 (and always under what the transport carries in one message), `maxKeys` 200
for `describe`, `maxRequestsPerSecond` 50 per channel, `callTimeoutMs` 30000 for a call that returns a promise.

**Events.** `on(ref, 'type', listener)` subscribes to an EventTarget-style source (`addEventListener` / `removeEventListener`) or an emitter-style one (`on` / `off`, or `on` / `removeListener`),
but only one that an allow-list entry **of its own** names: `allow.on: ['window.app.bus@ready', 'window@hashchange']` (`path@type`: **the source and the type are named exactly**; a wildcard in either is refused when the host is created, so list the types one by one; in `createPageHost({ expose })` the path is relative to the
root and `'@hashchange'` is the root itself). `get` and `call` never imply it, and neither does a wildcard in another list; the refused names, the entries that need naming, `authorize(who, op)` (`op.type` is the
event type) and the key capability `objects:ROOT:on` all apply. What is delivered is plain data, never the event and never a node or a handle: an **Event** becomes `{ type, timeStamp, isTrusted }` plus the fields the **host**
lists for that type (`eventFields: { hashchange: ['newURL', 'oldURL'], '*': ['detail'] }`) that the subscriber asked for in `{ fields }` (a field not listed is refused; each is copied as plain data and a node is left out);
an **emitter's** arguments become `{ type, args }` (what cannot be cloned is `null`). The listener is `listener(data, { type, seq, dropped })`; `await on(...)` resolves to the function that unsubscribes (`off(fn)`
does the same). Bounds, by name: `maxSubscriptions` 16 per channel (refused), `maxEventsPerSecond` 20 per subscription, `maxEventBytes` 16384 and `maxQueuedEvents` 100 per channel: an event over any of the last three
is **dropped and counted** (the rate and the queue are checked before anything of the event is read or copied, so a dropped event costs a counter), and the next one delivered says how many were lost before it (`dropped`). Events leave as notifications whose write waits for the channel's credit, so a slow reader fills the bounded
queue and then loses events, counted, instead of growing the page's memory. Every listener is taken out of the page's sources when the channel ends: the operator leaves, Stop, a navigation, a revoke. An error in the far
side's listener goes to its `onError` and stays there; the host's listener only copies and queues and cannot throw into the page's dispatch. Callbacks as arguments of a call are a separate facility (see [Callbacks](#callbacks)).

#### Handles

A root can opt in to **handles**: `exposeObjects({ roots, handles: { window: {} }, ... })`, or `createPageHost({ expose: { window: { mode: 'handles', allow } } })`. Values stays the default, and the opt-in is per root.
On such a root a function or an object that is not plain data (a class instance with state, a `Map`) comes back as an opaque `RemoteHandle` instead of a named non-value, and `use(handle)` makes a reference that stands on it:

```js
const cart = await win.app.cart;             // a RemoteHandle { type: 'Cart' } (what a plain value or a named non-value would have been)
await use(cart).add({ sku: 'A1' });          // the same object across calls; one request per chain, as ever
await use(cart).items.length;
await release(cart);                         // gives its place back; everything is released when the channel ends
```

- **The path-bound model.** A handle stands at the **path that produced it**: one got by `get window.app.cart` behaves as `window.app.cart`; one returned by calling `window.app.makeCounter` behaves as `window.app.makeCounter()`
  (the notation values mode uses for results), and its members as `window.app.makeCounter().inc`. Every operation through it is judged by the allow-lists for that path extended by the member, exactly as if the path were written out.
  **A handle never widens what a path grants**: if only `window.app.cart.add` may be called, `use(cart).items` is refused. Allow-list entries can name such paths (`call: ['window.app.makeCounter', 'window.app.makeCounter().inc']`).
  The always-refused names stay refused through a handle, and so do the entries that must name their path (`fetch`, cookies, storage, ...).
- **A handle is opaque and local.** Its id is 128 random bits (from `crypto.getRandomValues`; the page host uses the served window's). It is meaningful only on the channel that produced it, for the key that holds that channel: another
  channel, another key, a reconnect, or a guess finds nothing (`no such handle`). Nothing of it is enumerable on the far side; it is not thenable, and it cannot be sent as an argument.
- **Nodes and the window graph.** A DOM node, a window or a document is **not** handed out as a handle (it stays a named non-value) unless the root sets its own opt-in, `nodes: true`, which is control of the page. Even then the members that
  lead back up to the graph (`ownerDocument`, `defaultView`, `parentNode`, `parentElement`, `getRootNode`, `contentWindow`, `contentDocument`, `self`, `window`, `top`, `parent`, `frames`, `opener`, `globalThis`) stay refused
  until an allow-list entry names them; a wildcard does not.
- **A bounded table.** `maxHandles` (64) per channel, **refused by name on overflow, never evicted**; `release(handle)` is explicit; all of them go when the channel ends (the operator leaving, Stop, a navigation, a revoke). A far side's
  garbage-collection hints would be advisory only; none is used.
- **Previews.** `handle.preview` (a bounded list of up to 8 member names) is present only if a `get` entry names the handle's path, and lists only the names `describe(use(handle))` would list: those the allow-lists could walk to from there. Otherwise a handle says its type and nothing more.
- **Wide entries need an acknowledgement.** A wildcard (`*` or `**`) in `allow.call` or `allow.set` on a handles root lets a caller hold and reuse every object under it, so the host refuses to start with one unless the root says
  so, `handles: { window: { wideEntries: true } }` (in `createPageHost`, `wideEntries: true` beside `mode: 'handles'`), or lists the paths. A wildcard in `get` alone needs no acknowledgement. A values root is not affected.
- **Capabilities.** `objects:ROOT[:OP]` apply unchanged: an operation through a handle is the same `get`, `call`, `set` of the producing path (a key with `objects:window:get` can read through a handle and cannot call through it).
- **What a handle is not.** The host's real object stays in the page: calling a method runs the page's code with the caller's plain-data arguments, as for any `call`; a handle to an object with a powerful method is as powerful as that method's entry in `call`. A handle is
  a reference to something already reachable by a path, so it cannot reach more than the path's own entries; but a wide entry (`window.app.**`) covers every member of every object under it. Callbacks are one-way (see below).
- **Events through a handle** (`on(use(handle).bus, 'ready', listener)`, or `on(use(handle), ...)` when the handle is the source itself). The source is the handle's **producing path extended as written**, and it is judged exactly as a path subscription for that
  path would be: an `allow.on` entry that names that path and the type exactly (no wildcard in either), the key's `objects:ROOT:on`, and `authorize` (`op.text` is the extended path, `op.type` the type). **Never implied by `get` or `call`**, and never inherited: the same object reached by
  another path is a different path with its own entry. A node handle keeps its rules (no node handle without `nodes: true`; the graph members need an entry that names them). The subscription **ends with the handle**: `release(handle)` takes the page's listener out
  and drops what it had queued; it also ends with the channel, Stop, a navigation and a revoke, as a path subscription does. A handle released while its subscription was being authorized leaves no listener. `maxSubscriptions`, the rate, size and queue bounds and the drop counting are the same ones, shared with path subscriptions.
  The delivery is the same too: plain copies, never the event, never a handle.

A host says what it supports with its roots (`features`: `events`, `callbacks`, `callback-returns` when an entry lets a callback return a value, `types`, and `handles` and `handle-events` when a root opted in). A client does not send a function to a host that has not said it supports callbacks, nor use events on one that has not said so, nor subscribe through
a handle on one that has not said `handle-events` (0.50.0 and before; a named `unsupported` error, nothing is sent);
a handle-shaped answer from a host that never said it supports handles is the same error. A 0.47.0 host says nothing, so it counts as supporting none of them. A 0.50.0 client never sends a handle subscription (it refuses to write one), so it is unaffected by a 0.51.0 host.

#### Callbacks

A far-side **function passed as an argument** of a call is a callback, but only where the call's allow-list entry says so by ending in `(callback)`: `allow.call: ['window.app.subscribe(callback)']`. A call entry without it refuses a function
argument (`does not accept callbacks`), and a function nested inside an argument, a remote reference and a handle are refused where they are written. The page then receives a **stub**, a plain function it may keep and call:

```js
await win.app.subscribe((event) => console.log(event.n));   // the page's subscribe(fn) gets a stub; fn runs here, on the far side
await release(fn);                                          // kills the stub (also: the channel ending)
```

- **One-way.** The stub copies its arguments, queues a notification and **returns `undefined` at once**: the page cannot be made to wait for the far side, and the far side's return value is not delivered back. That is the rule for every entry that says only `(callback)`. The next bullet is the one way to get a value back, and only where the host wrote it.
- **Callback return values (#219), off unless the host opts in per entry.** An entry that ends in `(callback:returns)` (every function the call takes may answer) or `(callback:returns=0,2)` (only the functions at those argument positions; the others stay one-way) makes that stub return a **promise** of what the far side's function returned: `const ok = await stub(question)`. The page is never blocked and never waits unboundedly:
  - **The wait is bounded by the host**, from the call (queueing included): `limits.callbackReturnTimeoutMs`, 2000 by default and **at most 30000** (a larger value is a `TypeError` when the host is created). The host needs `timers` (`exposeObjects` and `createPageHost` supply them; `createObjectsServer` without `timers` and a returning entry is a `TypeError`).
  - **Every case that is not an answer is `undefined`**, and the promise **never rejects**: the timeout, an error thrown by the far side's function (its text stays on the far side, where `onCallbackError` gets it), a result that is not plain data (a function, a handle) or larger than `maxCallbackResultBytes` (16384), a call over the rate or size bound, a table that is full (`maxPendingCallbackReturns`, 8 calls waiting per channel, at most 64: the call is dropped, counted and **not sent**), a released callback, the end of the channel (Stop, a navigation, a revoke settle every waiting call with `undefined` at once and take the timers away), and a far side that did not say it can answer. So treat `undefined` as "no answer": a function that returns `undefined` is indistinguishable from a timeout, and code that asks "may I?" must treat anything but an explicit `true` as no.
  - **The value is plain data**, copied under the same rules as an argument (`maxDepth` 4, bytes, bytes arrays, no function, no handle, never an object with a prototype), and the page is handed the copy. A late answer after the timeout is ignored. An answer is for a request id the host gave on this channel, once; an answer for an id nobody waits for is counted against the request rate and changes nothing else.
  - **A far side that is slow or hostile can make the page wait at most `callbackReturnTimeoutMs` per call and at most `maxPendingCallbackReturns` calls at a time**; it cannot make the page wait for anything else. `host.callbackReturnStats()` (on what `attach` returns) says how many calls are `pending` and how many were `answered`, `timedOut`, `failed`, `refused` or `dropped`.
  - **Negotiation.** A host states `callback-returns` in the `features` of its `roots` answer only when an entry says it; a client says it answers by listing `callback-returns` in the `features` of its `roots` request. A host that has not been told never asks (the stub resolves `undefined` at once and the callback is delivered one-way), so a 0.51.0 client against a new host neither waits nor breaks, and a new client against a 0.51.0 host sends one extra optional field that it ignores. The `types` a host sends tell an entry as `(callback)` so a 0.51.0 client reads them; the generated types do not describe a returned value.
  - **What it does not do.** It does not make the answer true or safe: whatever the far side returns is data from the person or program on the other end, and the page's code that acts on it (`if (await ask())`) is what to write defensively. It adds no other direction: the far side still cannot call into the page except through the entries the host listed.
- **Plain values only.** The arguments are copied under the same rules as a result: plain data and bytes; what cannot be cloned (a function, a node, a class instance, a date) is `null`; never a handle.
- **Bounds.** `maxCallbacks` (16 per channel, refused by name), `maxCallbacksPerSecond` (20 per callback), `maxCallbackBytes` (16384 per call); a call over the rate, the size or the shared queue (`maxQueuedEvents`) is dropped and counted, and the next delivered call is preceded by
  `onCallbackDropped({ dropped })` on the client. The notifications go through the channel's credit like events. The same function sent again is the same callback.
- **Dead after the session.** A stub is dead after the channel ends (the operator leaving, Stop, a navigation, a revoke) and after `release(fn)`: calling it does nothing and is counted. A listener that throws on the far side goes to `onCallbackError` and never reaches the page.
- The call with callbacks is a `call` for `authorize` (`op.callbacks` is how many) and for the key's `objects:ROOT:call` capability. A callback is a channel for the page's own code to push plain values to the caller: it can send whatever the page's code puts in it, within the bounds, so list `(callback)` only on calls whose
  stub the page will use for what the caller should see.

#### An MCP face for allow-listed paths (#219)

An MCP client can use named paths of a root without the objects client: `exposeObjects({ roots, allow, mcp: { tools: [...] } })` (and, in a page host, `createPageHost({ expose: { window: { allow, mcp: { tools: [...] } } } })`, with paths relative to the root) makes **exactly the paths it names** into MCP tools:

```js
const handler = exposeObjects({
  roots: { window }, allow: { get: ['window.document.title'], call: ['window.app.cart.add', 'window.app.cart.clearAll'] },
  mcp: { tools: [
    { name: 'cart_add', description: 'Add a product to the cart', call: 'window.app.cart.add',
      inputSchema: { type: 'object', properties: { sku: { type: 'string', minLength: 1 }, qty: { type: 'integer', minimum: 1 } }, required: ['sku'], additionalProperties: false } },
    { name: 'page_title', description: 'The title of the page', get: 'window.document.title' },
  ] },
});   // clearAll is allowed by call and is NOT a tool: nothing is a tool by being allowed
const mcp = webmcpTools({ window, tools: handler.mcpTools, allow: handler.mcpToolNames });   // createPageHost does this itself; any host with `rpc: { mcp }` or serveMcpOverDuplex can
```

- **What a tool is.** A **call** of one named method (`call: 'window.app.cart.add'`), or a **get** of one named value (`get: 'window.document.title'`; add `readOnly: true` to skip the question for it); a literal member path (no wildcard, no path through a call result), that the allow-lists name for that operation and that needs no listing it does not have (checked when the host is created: a tool never widens
  the allow-list, and a path that is not listed there is a `TypeError`, not a silent tool). Each tool has a host-authored `name`, `description` and `inputSchema`, and `readOnly` (**only `readOnly: true` marks a tool read-only, a get included: with nothing said a tool asks the person like any other, because a getter can have effects**). `args: 'object'` passes the validated input as the call's one argument (the default when the schema lists properties), `args: ['a', 'b']` passes those properties as the arguments in order.
  There is no tool for an event, a handle or a callback, and none can be made: an argument is plain data, a result is plain data or an error (a function, or an object that is not plain data, is an error that says so, never a handle).
- **Arguments are validated before anything runs.** `inputSchema` is checked against the far side's arguments before the person is asked and before the page's function is called, by a small bounded subset of JSON Schema (`type`, `enum`, `const`, `properties`, `required`, `additionalProperties`, `items`, `minItems`, `maxItems`, `minLength`, `maxLength`, `minimum`, `maximum`, `anyOf`; depth 8, 2000 values; no key that climbs to a prototype). **A schema that uses another keyword
  (`$ref`, `pattern`, `oneOf`, ...) is refused when the host is created**, so what is advertised is what is checked. Write `additionalProperties: false`: with `args: 'object'` an extra property is passed to the page's function otherwise. The arguments then go through the same copy as an objects call.
- **The same approval, bounds and label as the WebMCP bridge**, because they are served by the same handler: a tool that is not marked read-only asks the person at the page first (`approve`, `prompt`; with no way to ask it is denied); `maxInputBytes`, `maxResultBytes`, `maxInflight`, `maxCallsPerMinute`, the call timeout, the schema size; every result is labelled untrusted page content (`_meta['wsh/untrusted']`); a page function that throws is an error result with its message and no stack.
  `onCall` sees the calls. Remember what a read-only mark is: the host's word. A getter that has effects is still a getter, and marking it read-only skips the question.
- **Two notations, both required.** A key lists and calls a tool only if its capabilities permit `mcp:TOOL` (or `mcp:*`) **and** the operation on that root (`objects:ROOT` or `objects:ROOT:call` for a call, `objects:ROOT` or `objects:ROOT:get` for a get): `capabilities="mcp:cart_add,objects:window:call"`. A key that has a capability line with `mcp:TOOL` and no `objects:` entry for the root sees no tool and can call none; a key with `objects:` and no `mcp:` entry cannot open the channel. A key with no capability line has both, as for every capability.
  The `objects:` grant is asked again when the tool runs, with the allow-list, the names that need listing and `authorize(who, op)` (`op.kind` is `get` or `call`): **a tool never widens what the objects client would be allowed for that key.**
- **What it does not do.** It does not make the page's function safe (it runs with the page's authority and the caller's arguments); it does not label a result as true, only as untrusted; it is no more than the allow-list plus the tool list plus the approval, and a wide allow-list entry under a tool path does not widen the tool (the tool names one path) but does widen the objects client. Wire: nothing new (the existing `mcp` channel and its methods); Rust hosts and clients have no `wsh-objects`, so there is no Rust equivalent of the host side,
  but a Rust `wsh --sealed --via ... mcp` reaches a page host's `mcp` channel and so lists and calls these tools like any others.

**The indicator is best effort.** The page host shows a visible element while a session is connected, puts it back if the page removes it, and has a Stop button. Page code can always remove or cover a DOM element, and a tool or a
function the caller may call runs with the page's authority. What holds is **Stop and revoke** (they close the channel from the page's own code, whatever is on screen) and **the key's capabilities and the host's allow-lists**.

**Threat model of `values` mode.** An allow-list of paths means what it says **only because nothing but cloneable values crosses**: a result can never be walked somewhere else, so what a session can
reach is exactly the paths the lists name (and, below a `get`, the plain data inside that value). That holds up to what the named paths themselves do:
- **Getters with side effects are still gets.** Reading an accessor property runs its getter, and setting one runs its setter; an entry that allows the path allows the effect. The copy of a value never runs a getter or a `toJSON`
  (an accessor member is left out).
- **A `call` runs the application's function with the caller's arguments**, with the page's authority: whatever it does, it does. List the functions you would hand to the caller. A wide entry means what it says:
  `window.**` reaches `window.Object.assign`, `window.history.pushState` and every method of every object under it (it still excludes the refused names above).
- **An event source runs the page's own `addEventListener` or `on`**, and a field of an event is read by name (an accessor on an event is a getter, as for `get`). Naming a source in `allow.on` hands the caller what
  that source emits, which for `window` or `document` can be every `keydown`, `input` or `message`: the host has to list the types (no wildcard is accepted), and should keep `eventFields` to what the caller should see (a `detail` or `data` field
  carries whatever the page put there).
- A Proxy used as a root runs its own traps for the paths that pass the allow-list, and for no others.
- The list is judged by path text. Give a root its real name: a root called `doc` that *is* the `document` is not recognised as `document.cookie` by the entries that must name it.
- It does not protect against the page's own code, against a function reachable by a listed path doing something unlisted, or against what a person at the keyboard can see. The remote caller sees results, which may hold text
  written by third parties.
- A sealed session, a key login and a visible indicator (the page host) are what keep a relay and an unknown caller out; `authorize` is where an embedder asks the person.

Size: see the size table (`npm run size`) for `@johnhenry/wsh/objects` (it contains the client and the checks the host runs on a type map), `@johnhenry/wsh/objects-types` and the page entry point. A capability per root and operation (`objects:ROOT[:OP]`) is described under [per-key capabilities](#authorized-key-options-122).
A dial-out form of the page host (`createPageHost({ connect })`, an operator that listens) is described under [A page as a host](#a-page-as-a-host-johnhenrywshpage-190).

#### Typed remotes (#219)

`@johnhenry/wsh/objects` ships `.d.ts`; `client.openObjects<T>()` returns `T`, so a typed Proxy is a `T` you give it. Three ways, from least to most generated:

1. **Write the value types.** `Remote<T>` maps a value type to the reference type (it `await`s to the value, has the members as references, and its methods return references); `RemoteRoots<T>` does it for the roots:
   `const { shop } = await client.openObjects<RemoteRoots<{ shop: Shop }>>(); const n: number = await shop.cart.add({ sku: 'A' });`. It says what you believe the host exposes; the host's allow-lists still decide. A reference is `PromiseLike`, not a `Promise`
   (there is no `catch` or `finally` on it: `ref.catch` is a remote property), and arguments stay plain data. `RemoteHandle<T>` carries a value type to `use(handle)`.
2. **Generate them for the key that connects.** `describeRootTypes(description, { name })` from `@johnhenry/wsh/objects-types` is a **pure function** that returns the text of a `.d.ts` for one root, and `rootDescription(page.window)` fetches the `description`
   (the host's `types` answer): the host's allow-list entries for that root, narrowed by **this key's** `objects:ROOT:OP` capabilities, and the host's type map. A path appears in the file only if an entry names it for an operation the key holds; an operation the key lacks,
   a path no entry names, and a member the host refuses are not there at all (not even as `never`). A plain value is `RemoteValue<unknown>` (a `PromiseLike<unknown>`), a call is `RemoteCall<unknown[], unknown, ...>` (`(...args: unknown[]) => PromiseLike<unknown>`, continuing as the members the allow-list names under `f()`),
   a wildcard (`*`, `**`) is `RemoteUntyped` (`any`: the members behind it are not guessed), `allow.on` and `eventFields` become typed `on` overloads (a source offers its listed types, and a listener gets `{ type, timeStamp, isTrusted, ...fields }` or `{ type, args }`),
   and an entry in `allow.set` makes `set(ref, key, value)` check the key. Use it as `client.openObjects<{ window: WindowRemote }>()`.
3. **Add precise types as the host.** `exposeObjects({ types: { 'window.app.cart.add': { args: '[item: { sku: string }]', result: 'number' }, 'window.document.title': { value: 'string' }, 'window.app.bus@ready': { data: '{ n: number }' } } })`
   (`createPageHost({ expose: { window: { types } } })` takes the same with paths relative to the root). `value` is the awaited value of a get (or the value a set takes), `args` a tuple and `result` the awaited value of a call, `data` what an event listener receives; a text may use `RemoteHandle<{ ... }>`.

**The host's type text is untrusted text.** It travels to the far side and is written into a file, so the far side checks it again: `checkTypeText` accepts a conservative subset of type syntax (identifiers, literals, and the punctuation of object, tuple, function, union, intersection, generic, conditional and indexed types) and refuses a new line or anything
outside printable ASCII, comments (`//`, `/*`), `\`, backticks, `@`, `#`, the words `import`, `export`, `require`, `declare`, `module`, `namespace`, `global`, `typeof`, `class`, `function`, `enum`, `interface` and `eval`, unbalanced or mismatched brackets, a `;` outside braces and a `,` outside any bracket (so a text cannot close the declaration it sits in or add a member to it).
Bounds: 1024 characters a text, 256 entries and 32 KiB for a root, 16 levels of nesting. A text is also refused unless an allow-list entry names its path for the operation it types, **when the host is created** and again when the far side builds the file. The text is **never evaluated**: it is copied into the string `describeRootTypes` returns, and nothing is written to a file
unless you do it (the CLI below writes only when given `--out`, and not over an existing file without `--force`). A path segment that is not an identifier is written as a quoted name.

**What the types do not promise.** They are advisory and erased before anything runs: a type never widens what the host allows, and `authorize`, the always-refused names and the paths that must be named (`fetch`, cookies, storage, ...) still refuse at call time whatever the file says; a type can be wrong (the host's text is what the host believes, and
a hand-written `T` is what you believe); `authorize` is dynamic and is not reflected; a wildcard region is untyped; whether a value arrives as a plain value, a named non-value or a handle depends on the page's data at run time, which no file can say (on a root with handles a get is `unknown` unless the host typed it `RemoteHandle<...>`); and the file describes the key that fetched it:
another key gets another file, and a key that changes or expires changes the answer. The `types` answer tells a key the allow-list entries it may use, which is what `describe` would reveal path by path and nothing about a member the key may not reach.

**The CLI.** `wsh-objects-types [--root NAME] [--name TYPE] [--out FILE [--force]] [--sealed] [--host-key KEY] [--identity FILE] [user@]<url>` (the package's second bin; JavaScript only) connects like `wsh-mcp` does, asks for the description of one root and prints the declarations, or writes them with `--out`.
The Rust `wsh --sealed [--via RELAY] objects user@host types ROOT` (next release after `rust-v0.18.0`) asks the same question and prints the description as JSON (`wsh_client::objects::ObjectsClient::root_description`); it has no generator for `.d.ts` text. A host before 0.51.0 does not state the `types` feature in the `features` of its `roots` answer, and `rootDescription` then refuses with a named `unsupported` error without sending anything.

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
plain message from the host is dropped (counted in `client.droppedMessages`, and reported to `client.onDrop({ reason, messageType })`; nothing is written to the console), a frame that does not open ends the connection (`onError`, then `onClose`), `openStream()`
is refused and datagrams are neither sent nor heard (UDP uses the reliable path). `'auto'` is not a guarantee, for the reason above;
`true` is.

The Rust `wsh-server` is a responder too: `[server] seal_session = "off" | "offer" | "require"` (default `off`: no feature is
advertised and no released client is affected; `offer` and `require` need `host_key`, else the config is refused at start). On a
WebSocket connection it advertises `e2e-session` (and `e2e-session-required` with `require`), and after a KEY login it answers the
signed key exchange (it verifies the login key's signature, signs its reply with the host key) with the same `SealGate` the CLI uses;
from then on every control message but ping/pong is an `EncryptedFrame` both ways, gateway data included, and a frame that does not open
closes the connection. `offer` serves a client that never asks as before. `require` serves nothing in the clear: a plain message before
the key exists is answered with an error and the connection is closed, a password login is refused, and WebTransport connections and
WISP tunnels are refused (they cannot be sealed; connect over WebSocket). **While `seal_session` is on, the typed rpc channels (`wsh-host`, and `wsh-fs` when `[rpc] fs_root` is set)
are offered in virtual data mode** (#191): the server states `rpc-virtual` instead of `rpc`, and a channel rides `SessionData` (inside
the seal on a sealed session, in the clear on an unsealed one under `offer`) metered by credit, with the `rpc:NAME`, `fs:read` /
`fs:write` and file-transfer checks of stream-mode rpc unchanged. With `seal_session` off (the default) rpc is stream-mode, exactly as before.
A client that only knows stream-mode rpc finds no `rpc` and is refused before anything is sent; see [RPC channels](#rpc-channels-object-mode). WebTransport on an
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
**Browser and Node halves.** `@johnhenry/wsh/pipe-relay` itself is browser-safe -- `pipeUrl`, `newRendezvousId`, `watchPairing` and a relay's
`accept()` over sockets you hold bundle for a page (the bundle test covers it, next to `./memory`). `listen()` (an HTTP server through the optional
`ws` package) is a second module, `pipe-relay-node.mjs`, loaded when you call it, so a bundler never follows it. `createPipeRelay().listen()` works as it did.

**Knowing a host was paired.** A host that has dialled and is waiting cannot otherwise tell when its operator arrived. Dial with
`pipeUrl(relay, id, 'host', { notifyPaired: true })` (`?role=host&paired=1`; with your own HTTP server, `relay.accept(socket, { id, role: 'host', notifyPaired: true })`),
wrap the socket, and await the promise:

```js
const ws = new WebSocket(pipeUrl('wss://relay.example', id, 'host', { notifyPaired: true }));
await new Promise((r) => ws.addEventListener('open', r, { once: true }));
const { socket, paired } = watchPairing(ws);                   // before anything else is attached
await server.accept(socket);                                   // the wsh host never sees the signal frame
await paired;                                                  // the operator is here (rejects if the socket closes first)
```

The relay sends the host ONE text frame, `wsh-pipe/1 paired`, when the operator arrives and before anything the operator said; everything else on a pipe is
binary, so it cannot be mistaken for wsh bytes. It is opt-in per host and costs nothing otherwise: a relay older than this ignores `paired=1` and never sends it (then
`paired` never settles and the connection works as before, so bound the wait with your own timer if you need to know), and a host that did not ask is sent nothing.
It tells the host the operator is there, not who it is: the handshake still decides that.

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
      --sealed             seal the whole session end to end; refuse a host that cannot (key login only)
      --host-key KEY       pin the host (hex fingerprint or ssh-ed25519 line); unpinned, it warns on stderr
      --no-reconnect, --reconnect-attempts N, --timeout MS
```

An MCP client configuration:

```json
{ "mcpServers": { "remote": { "command": "wsh-mcp", "args": ["--identity", "/home/me/.wsh/keys/default.pem", "--host-key", "<fingerprint>", "wss://host.example:4422"] } } }
```

**Dialling a host behind a pipe relay (a pod's services host, a page host).** Both CLIs dial the operator side of a [pipe relay](#a-pipe-relay-johnhenrywshpipe-relay-118) directly. `wsh-mcp` takes the relay URL as its URL, since that is a `ws://` / `wss://` URL: `wsh-mcp --sealed --host-key <host fingerprint> --identity KEY wss://relay.example/r/<rendezvous id>` (the URL must end in `/r/<22-128 base64url characters>` and must not be the `?role=host` one). The Rust `wsh` has a flag for it: `wsh --sealed --via wss://relay.example/r/<id> mcp user@host` (and `wsh --via wss://relay.example/r/<id> user@host [command...]`), where `user@host` stays the identity the host key is recorded under. A host behind a relay that is a page or a mesh peer serves sealed sessions only, so pass `--sealed` and pin `--host-key`.

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
wsh-host` works (it is the same rpc channel, and a handy check). `wsh mcp` follows what the host states: `rpc` is a data stream, `rpc-virtual` (a sealed session, a host in a page behind a pipe relay) rides
`SessionData` with credit (#191), so `wsh mcp --sealed` and `wsh --via <pipe relay> mcp` work against a JS host, as the npm `wsh-mcp --sealed` does. Not covered: WebTransport (`https://`) opens the channel's stream but the Rust client has only
been run against WebSocket hosts.

**Rust: `wsh objects`** reads and drives a host's remote objects (`wsh-objects`, written down in `spec/objects.md`; `rust-v0.18.0` carries it). It is a client only, for **sealed sessions only**:

```
wsh --sealed [--via RELAY] objects user@host roots
wsh --sealed [--via RELAY] objects user@host get window.document.title
wsh --sealed [--via RELAY] objects user@host call window.app.cart.add '{"sku":"A1"}' 2   # each argument is one JSON value
wsh --sealed [--via RELAY] objects user@host set window.app.n 5
wsh --sealed [--via RELAY] objects user@host snapshot window.app.state --depth 3
wsh --sealed [--via RELAY] objects user@host describe window.app
wsh --sealed [--via RELAY] objects user@host watch window.app.bus@ready --field detail --count 3
wsh --sealed [--via RELAY] objects user@host types window   # what this key may do on the root, as the host describes it (needs the host to state `types`)
wsh --sealed [--via RELAY] objects user@host session     # JSON requests on stdin, one answer line each: one connection, so a handle, a subscription or a callback can be held across calls
```

JSON on stdout. Plain data is printed as the JSON it is; bytes as `{"$bytes":"<base64>"}`, what the host could not clone as `{"$nonValue":{"kind":"function","type":"fn"}}`, a handle as `{"$handle":{...}}` (a page can build plain data that looks like these: this is an inspection format; use the library where that matters).
**Text from the page is never interpreted**: names, strings, previews and error messages are printed as JSON strings in which every control character, C1 control, line or paragraph separator and bidirectional-text control is a `\uXXXX` escape. `watch` prints one line per event, `{"seq":N,"dropped":N,"dropped_here":N,"data":...}`: `dropped` is what the host dropped before it (its bounds: rate, size, queue), `dropped_here` what this side dropped when its bounded queue was full.
Exit status: 0 done; 1 other failure; 2 usage, or not `--sealed`; 3 the host refused (its allow-lists, a key's `objects:` capability, a bound); 4 not found; 5 unsupported (the host does not state the channel, or `events` / `handles` / `handle-events` / `callbacks` / `types`, which are refused locally before anything is sent). `wsh --help objects` lists the rest.

In a `session`, one line per request and one answer line each, in order. Events and callbacks live there because they need one connection: `{"op":"watch","path":"window.app.bus","event":"ready"}` answers `{"ok":true,"result":{"subscription":"s1"}}` (through a handle: `{"op":"watch","handle":"h1","path":"","event":"ready"}`; the host must state `handle-events`, and releasing the handle ends the subscription); `{"op":"next","subscription":"s1"}` waits (`timeoutMs`, default 10000) for the next event; `{"op":"callback"}` answers `{"callback":"c1"}`, which a call passes with `{"op":"call","path":"window.app.listen","args":[null],"callbacks":[[0,"c1"]]}` (the host must state `callbacks`, and the allow-list entry must end in `(callback)`); `{"op":"next","callback":"c1"}` waits for the host's next call of it; `unwatch` and `{"op":"release","callback":"c1"}` end them.

In Rust code, `wsh_client::objects::ObjectsClient::open(&client)` gives `roots()`, `root(name)`, `root_description(root)` (the `types` answer, as plain data), `callback(capacity)` and a `Target` with `get` / `call` / `call_with` (callbacks among the arguments) / `construct` / `set` / `snapshot` / `describe` / `resolve(Chain)` (a whole chain such as `app.getCart().items` is one request) and `subscribe` (a bounded `Subscription`, from a root or from a handle's `target()`), with typed `ObjectsError`s (`Refused`, `Limit`, `NotFound`, `Unsupported`, ...) carrying the host's `reason`, values as a serde-friendly `Value` (bytes native), `Handle`s (released with `release()`, when dropped, and when the session ends) and `Callback`s (a bounded queue of the host's calls; one-way: the host gets no return value).
**What it cannot do:** serve objects (`wsh-server` has no page host and no `wsh-objects` handler, and will not: see [why](spec/objects.md#11-what-the-released-peers-do)); WebTransport and Windows are not exercised. It protects nothing the host's allow-lists do not: it only speaks to a host that chose to expose objects. A callback hands the host's code a way to push plain values at this process: they are bounded (this side's queue, the host's rate and size limits) and untrusted like every other byte from the host, and a `session`'s `next` prints them as escaped JSON.

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
- **A refused login is a `WshAuthError`, a failed connection a `WshConnectionError`** (both `Error`s, with the same message as ever). `WshAuthError` has
  `code` (`AUTH_UNAUTHORIZED | _BAD_SIGNATURE | _METHOD_DISABLED | _RATE_LIMITED | _KEY_EXPIRED | _BINDING_REQUIRED | _NOT_SEALED | _BAD_REQUEST`, else
  `AUTH_FAILED`), `reason` (what the host said) and `refusal`, the reason the host reported to its own `onRefused`. The wire carries only the host's
  words, so `refusal` is recognised from the wording of the Node host and the Rust `wsh-server` (a test keeps the table in step with the Node host's
  `onRefused` codes); a host that words it otherwise gives `AUTH_FAILED` and `refusal: null`, with the text in `reason`. `WshConnectionError` has `code`
  `CONNECTION_FAILED` (no transport opened; `attempts` lists each) or `HANDSHAKE_TIMEOUT`.
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
import { createWshServer, hashPassword, passwordVerifier } from '@johnhenry/wsh/server';

const stored = { alice: await hashPassword(process.env.ALICE_PASSWORD) };  // once, offline: keep the strings, not the passwords
createWshServer({
  auth: {
    password: passwordVerifier(stored),   // or any (username, password) => boolean | Promise<boolean>
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
host. A host with only `password` refuses key logins and
vice versa; with neither configured every connection is refused.

**Storing the passwords.** `hashPassword()` / `passwordVerifier()` (Node entry point only, `node:crypto`) store a password as a PHC
`$scrypt$ln=16,r=8,p=1$<salt>$<hash>` string: scrypt (memory-hard, 64 MiB by default), a random per-user salt, a constant-time
comparison, and the same derivation for an unknown user as for a wrong password, so neither the answer nor the time says which
users exist. An old unsalted `sha256:<hex>` entry is refused (with a warning that names the user, never the hash) unless
`allowLegacySha256: true`, which keeps it working with the warning until it is replaced. The Rust `wsh-server` does the same with
Argon2id (`wsh-server hash-password`, the password from standard input or a no-echo prompt, never an argument); the two formats are
not interchangeable. **Not covered:** this protects the stored file, not the wire (the password still travels inside the connection,
see the Security model); `scrypt` is not available to a host that lives in a page, whose `auth.password` stays a callback and whose
hash is yours to choose (WebCrypto offers PBKDF2, not scrypt or Argon2; use a high iteration count and a per-user salt); and the
throttle's counters are per process.

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

**Virtual data mode (#191).** On a connection with no client-opened data streams -- a host behind a relay (`createReverseHost`,
`ReverseAccept.features`), a page host served with `dataStreams: false`, and every **sealed session** -- the same channel rides the control
plane: the same `Open { kind: 'rpc', command: <protocol> }`, the same CBOR sequence, in `SessionData` (inside `EncryptedFrame` when the
session is sealed, so a relay sees neither method names nor payloads). The host states `rpc-virtual` **instead of** `rpc`, with the same
`rpc-protocol:<name>` and `rpc-max-message:<bytes>`; `openRpc()` picks the form from what the host states and callers change nothing. Because
the control plane has no flow control, the channel carries its own: each direction starts with `RPC_CREDIT_WINDOW` (256 KiB) of credit,
returned in bytes as the receiver takes data in (`GatewayCredit` with `gateway_id` = `0x80000000 | channel_id`), so a reader that does not
read bounds the sender, a message larger than the window still arrives, and a peer that overruns its credit has the channel closed. The size
cap is enforced from the CBOR header, before a message is assembled. `wsh-mcp --sealed` (and `runMcpStdioBridge({ sealSession: true })`)
reach an `mcp` channel on a sealed host or a host behind a pipe relay. A released client looks for `rpc`, which a virtual-mode host does not
state, so it refuses with `UNSUPPORTED_PROTOCOL` before sending anything; a released host never states `rpc-virtual`, so this client uses
streams there. What it does **not** change: nothing about who may open a channel (`rpc:<protocol>` capabilities, `authorize`), and over an
unsealed relayed session the relay still sees the traffic (seal it).

**Negotiation.** The host advertises `rpc` (or `rpc-virtual`, above), one `rpc-protocol:<name>` per
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
the handler's job (`-32003`; `ctx.user` / `ctx.fingerprint` identify the caller; `ctx.capabilities` is the caller's key's capability
list, or `null`, and `ctx.permits({ kind: 'mcp-tool', tool })` asks afresh whether the key's options and capabilities allow a request,
on the JS hosts; a handler that narrows by `permits` declares `handler.capabilityScoped = true`, see
[A page as a host](#a-page-as-a-host-johnhenrywshpage-190)).
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
| `RpcChannel` / `RpcError` | Typed RPC channel (JSON-RPC 2.0 over a CBOR sequence): `client.openRpc(protocol)`; `RPC_FEATURE`, `RPC_VIRTUAL_FEATURE`, `rpcProtocolFeature(name)`, `RPC_ERROR`, `CborSequenceDecoder` |
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

Four crates, workspace-versioned (currently `0.18.0`):

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
never into the command's stdout. A plain `ws://` URL is accepted only for a loopback host.

**The server's certificate is verified**, on both transports. `wss://` and `https://` (WebTransport) use the platform trust store; `SSL_CERT_FILE` points the
`wss://` check at another certificate. A WebTransport server with a self-signed certificate (`wsh-server --generate-cert`) is reached by pinning it:

```sh
wsh --cert-hash "$(openssl x509 -fingerprint -sha256 -noout -in ~/.wsh/cert.pem)" alice@host ls   # also: 64 hex digits, colons optional
```

`wsh-server` prints the same hash at start-up. `--cert-hash` is repeatable (the current and the next certificate across a rotation) and has the semantics of
`serverCertificateHashes`: the certificate's SHA-256 must be one of the pins, with an ECDSA P-256 key and a validity of at most 14 days (the dev certificate is
13), and no certificate authority is consulted. It applies to `https://` only: with a `wss://` URL it is refused rather than ignored. A single pin is also the
`cert-hash` [channel binding](#security-model) kind, which `--require-channel-binding` can then be satisfied by. `ConnectConfig.cert_hash` / `cert_hashes` are the
same for the library. **Development only:** `--insecure-skip-cert-verification` (`ConnectConfig.insecure_skip_cert_verification`) turns the check off
for WebTransport, prints a warning on every connection, and is refused together with `--cert-hash` and with a password login (a password cannot be sealed end
to end, so it would go to whoever answers the unverified connection). A login by key is still covered by the host-key check (`known_hosts`, `--host-key`)
and the channel binding; a host that proves no key is simply not authenticated in this mode.

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
| Typed RPC channels (`openRpc`, `rpc` sessions; `wsh-host`, `wsh-fs`, `mcp`) | `WshClient.openRpc()`, `RpcChannel` | Rust `wsh-server` (`rust-v0.4.0`+): `wsh-host`, and `wsh-fs` when `[rpc] fs_root` is set. **Client:** `WshClient::open_rpc(protocol)` in `wsh-client` (the next `rust-v` release; #127) returns an `RpcChannel` that sends and receives JSON-RPC messages (`rpc_offer()` tells what the host serves); it opens the channel's data stream over WebSocket/QMux (and WebTransport, not exercised against a host) and enforces `rpc-max-message`. It does not correlate requests or interpret `$/cancel` / `$/progress` (its one user, `wsh mcp`, passes MCP through), and there are no typed `wsh-fs` helpers in Rust (the Rust file commands use `FileOp`) | **No wire change**: `Open { kind: 'rpc', command: <protocol> }` plus `rpc*` `ServerHello` features, negotiated so it fails fast elsewhere; the Rust server serves it on WebSocket/QMux only. **Virtual data mode (#191; the next `rust-v` release): both sides.** `RpcOffer` reads `rpc-virtual` and `open_rpc` chooses the form from what the host states (a host that states `rpc` is opened with a stream as before); a virtual-mode `RpcChannel` writes `SessionData` and `GatewayCredit` (`gateway_id = 0x80000000 | channel_id`, 256 KiB per direction, returned as `recv()` takes messages in, so a slow reader bounds the sender; an overrun closes the channel; the size cap is checked from the CBOR header). `wsh-server` with `seal_session` on states `rpc-virtual` instead of `rpc` (it no longer withholds rpc), with the checks stream-mode rpc applies (`rpc:NAME`, `fs:read` / `fs:write`, file-transfer). A released Rust client looks for `rpc`, finds none, and refuses before sending anything. (`rpc` is now listed in the spec's `ChannelKind`; the bytes are what they were, the Rust server already read the kind from the raw message) |
| MCP over stdio for MCP clients that launch a command (#127) | `wsh-mcp` (the package's `bin`) and `runMcpStdioBridge()` from `@johnhenry/wsh/mcp-stdio`: opens the host's `mcp` rpc channel, reconnects, a clear error when the host offers none | `wsh mcp [user@]host\|URL` (the next `rust-v` release): the same bridge, behaviour for behaviour (`--channel`, `--host-key`, reconnect with `initialize` replayed, in-flight requests answered with an error, 200 held messages, exit 2 with the channels the host offers). Identity is `-i NAME` (a `wsh keygen` key), the host is pinned by `known_hosts` or `--host-key`, `--via` works, and so does `--sealed` and a host in a page behind a pipe relay (rpc in virtual data mode, #191; `test/rust/wsh-rpc-virtual.test.mjs`). **`wsh-server` serves no `mcp` rpc channel, so `wsh mcp` to it exits 2 and says it offers `wsh-host`** (use `wsh tools` there: it answers `McpDiscover` / `McpCall`) | **Unified** -- no wire change (the channel is #85's); tested against a Node host and a memory host with the MCP SDK's stdio client (`test/rust/wsh-mcp.test.mjs`) |
| Exec stdin + EOF, separate stderr | `exec({ stdin })`, `session.closeStdin()`, `session.onStderr` | `SessionOpts { stdio: Some("pipes") }`, `WshSession::read_stderr()` / `close_stdin()`; `wsh host command` uses them whenever its stdin is a pipe or a file and the host offers `exec-pipes` | **Wire-unified, negotiated** (#105): `Open.stdio = "pipes"` + `OpenOk.stderr_channel_id` + zero-length `SessionData` as EOF, offered by the `exec-pipes` `ServerHello` feature. `@johnhenry/wsh/server` needs none of it (stream-mode EOF); the Rust `wsh-server` (`rust-v0.5.0`+) runs such an exec on pipes, everything else on the PTY. Against a host without `exec-pipes` the CLI still forwards stdin, but cannot tell the command it ended |
| Signals and resize for a one-off command | `session.signal()`, `session.resize()` | `wsh host command` forwards SIGINT/SIGTERM/SIGHUP (the same signal twice disconnects); `wsh --tty host command` also forwards terminal resizes | **Wire-unified** (`Signal`, `Resize`). The Rust `wsh-server` delivers `Signal` (#145) to a pty session's foreground process group (what ^C reaches) and to an exec-on-pipes command's own process group, for `HUP INT QUIT TERM KILL USR1 USR2 WINCH CONT STOP TSTP ALRM` (with or without `SIG`); another name is ignored, and only the control attachment of the connection that owns the channel can send one. Not delivered on Windows |
| Dial target | a URL | `wsh [user@]host` (dials `https://` then `wss://` on `--port`), or a full URL: `wsh wss://host:8443/rendezvous/ab12 command`, `ws://127.0.0.1:PORT/` | **CLI-only convenience**: a URL is dialled exactly as given (no transport fallback; `--port` and `--transport` do not apply). Plain `ws://` is accepted only to a loopback host |
| Host that runs in a browser page (`createMemoryHost`, `@johnhenry/wsh/reverse`) | yes, with injected `pty` / `fs` / `hostKey` | no (a Rust host is a process) | **JS-only**. A Rust *client* can operate such a host only with `dataStreams: false` (#132): the released Rust client over WebSocket cannot open QMux data streams, and says nothing in `Hello` that a host could use to decide. `wsh scp` works against such a host with the Rust client of the next `rust-v` release (it speaks `FileChunk`, #140); a released `rust-v0.11.0` or older `wsh scp` hangs against it (`wsh ls` and exec work) |
| A page's WebMCP tools served as MCP, behind a pipe relay (#190) | `createPageHost`, `webmcpTools`, `captureWebMcp` from `@johnhenry/wsh/page`; the far side is `wsh-mcp --sealed` or `openRpc('mcp')` | the far side only: `wsh --sealed --via <relay>/r/<id> mcp user@host` (the Rust CLI, `rust-v0.17.1`+) lists and calls a page host's tools (`test/rust/wsh-mcp-page-host.test.mjs`); the Rust `wsh objects` is a `wsh-objects` client (next row), and no Rust host serves either | **JS-only** host (a page); the far side is unchanged wire (`mcp` rpc in virtual mode, #191) |
| A page host that dials an operator that listens, instead of a relay (#219): `createPageHost({ connect })` | `@johnhenry/wsh/page`; the operator is any process that accepts the socket and logs in as the client (`connectWshOverDuplex` from `@johnhenry/wsh/duplex`) | none: the Rust CLI has no listening operator mode (`wsh --via` dials a relay's operator side), so a Rust far side cannot be the listener | **JS-only**, no wire change: the same handshake and sealed session over a socket the page opened, URL as written |
| Remote objects by path, `values` mode (#190): `wsh-objects`, `client.openObjects()` | `exposeObjects` / `createObjectsServer` / `createPageHost({ expose })` host side; `get`, `set`, `call`, `construct`, `snapshot`, `describe` far side (`@johnhenry/wsh/objects`) | **Client only** (`rust-v0.18.0`, #219): `wsh_client::objects` (`ObjectsClient`, values mode, events with a bounded `Subscription`, handles; from the release after `rust-v0.18.0`: events through a handle, callbacks, `root_description`) and `wsh --sealed [--via RELAY] objects user@host roots\|get\|call\|set\|snapshot\|describe\|watch\|types\|session` (sealed sessions only; JSON on stdout; exit 3 refused, 4 not found, 5 unsupported); a feature the host does not state is refused locally. Callback return values (`(callback:returns)`, a JS host notation) are not asked of it: it never lists `callback-returns`, so a callback it passes stays one-way. Not planned: a host in `wsh-server` (it has no object graph to expose, see `spec/objects.md` section 11); it serves no `wsh-objects` and refuses an `objects:` key capability. The wire is `spec/objects.md`; tested against a real page host through a recording relay (`test/rust/wsh-objects.test.mjs`) | **JS host, Rust or JS far side**; an rpc protocol on the existing `rpc` channel (no new message or feature string), so a released peer simply does not offer or open it. The Rust codec gained a CBOR-value read path so byte strings survive (the existing `rpc` channels still reject them) |
| Events through a handle (#219): `on(use(handle).path, type, listener)` | `@johnhenry/wsh/objects` (`exposeObjects({ handles })`); the host states `handle-events` in the `features` of its `roots` answer | **Client only** (the release after `rust-v0.18.0`): `Target::subscribe` on a handle's `target()` and, in `wsh objects session`, `{"op":"watch","handle":...}`; refused locally unless the host states `handle-events`; releasing the handle ends the subscription. No Rust host | **JS host**; a new `subscribe` parameter (`handle`) on the existing `wsh-objects` rpc channel, offered only to a client that saw `handle-events`. A 0.50.0 host does not say it, and a new client then refuses to subscribe through a handle with a named `unsupported` error without sending anything; a 0.50.0 client cannot write such a request |
| Typed remotes (#219): `describeRootTypes`, `rootDescription`, `Remote<T>`, `wsh-objects-types` | `@johnhenry/wsh/objects` (the `types` method, the `types` option, `Remote<T>`, `RemoteRoots<T>`), `@johnhenry/wsh/objects-types` (the pure generator), the `wsh-objects-types` bin | **Client only, the data not the generator** (the release after `rust-v0.18.0`): `ObjectsClient::root_description` and `wsh objects types ROOT` print the host's `types` answer as JSON; refused locally unless the host states `types`. No `.d.ts` generator and no `Remote<T>` in Rust; no Rust host | **JS host**; a new `types` method on the existing `wsh-objects` rpc channel and a `types` string in the `features` of its `roots` answer (no new message type or `ServerHello` feature). A 0.50.0 host does not state it, and a new client then refuses with a named `unsupported` error and sends nothing; a 0.50.0 client never calls it |
| An MCP face for named object paths (#219): `exposeObjects({ mcp: { tools } })`, `createPageHost({ expose: { ROOT: { mcp: { tools } } } })` | `@johnhenry/wsh/objects` (`handler.mcpTools`, `server.invoke`) served by `webmcpTools` / `serveMcpOverDuplex` on the `mcp` channel; the far side is any MCP client (`wsh-mcp --sealed`, `client.openRpc('mcp')`) | the far side only: `wsh --sealed --via <relay>/r/<id> mcp user@host` lists and calls these tools like any `mcp` tool; no Rust `wsh-objects` host | **JS-only host**; **wire: nothing new** (the existing `mcp` rpc channel and its methods, no feature string), so any released MCP-speaking peer reaches it |
| Interactive shell UI | none -- this SDK is a protocol client, not a terminal emulator; pair with xterm.js/ghostty-web | `wsh connect`, `wsh sftp` (line-oriented REPL) | **Deliberately not unified** -- a browser embeds a terminal widget the host page owns; a CLI process owns its own TTY |
| Attach / resume | `attachSession()`, `resumeSession()`, `WshSession.seq` | `attach_session()`, `resume_session()` | **Wire-unified** (`Attach`/`Resume`/`Presence`); `seq` = cumulative output bytes. `@johnhenry/wsh/server` honours `last_seq` (bounded ring, gap errors) and answers Presence with `channel_id`/`seq`; the Rust `wsh-server` does the same (`rust-v0.2.0`+; fixed 256 KiB ring) |
| Reverse-connect / relay peer | `connectReverse()`, `trustRelayPeer()`; `@johnhenry/wsh/server`: `relay` option and `createReverseHost()` | `wsh reverse`, `wsh agent` (persistent, with startup-unit install) | **Wire-unified** (registration, discovery, signed peer records); **daemonization is CLI-only** -- a browser tab cannot be a background OS service. The Node relay is default-deny and bridges one operator per peer unless `maxOperatorsPerPeer` is raised (`busy:` reasons say so); E2E and bridged feature gates need `rust-v0.3.0`+ on the Rust side. **Several operators per peer (#93): both relays** (`maxOperatorsPerPeer`; `[relay] max_operators_per_peer`, default 1) **and both peers** (`createReverseHost({ maxOperators })`; `wsh --max-operators n reverse` / `agent run`, default 1), negotiated by `relay-multi-operator`; a Rust peer serving several operators does not seal bridges (see the reverse-mode notes), and the Rust relay leaves a peer connected when its operator leaves. The signed `KeyExchange` (`e2e-sign`) is carried by the Rust relay too |
| Post-quantum E2E (experimental) | `initiateE2E()` (WebCrypto ML-KEM-768 or `@noble/post-quantum` fallback) | `E2eKeyExchange` (`ml-kem` crate) | **Wire-unified** algorithm and transcript; key material backends differ by platform necessity |
| Unix-domain socket forwarding, both directions; named endpoints (#120) | `client.openUnix()`, `listenUnix()`, `forwardUnix()` (Node: `-L`/`-R` shapes with unix and TCP ends mixed), `openEndpoint()`; host: `gateway: { unix, endpoints }`, `createMemoryHost({ endpoints })` | `wsh-server` serves `OpenUnix`/`ListenUnix` (`[gateway] unix_connect`, `unix_listen`, `unix_replace_stale`, `unix_max_listeners`; same policy as the Node host); `wsh-client` has `open_tcp`/`open_unix`/`open_endpoint`/`listen_unix`/`listen_tcp`; CLI `wsh -L` / `-R` / `-N` with TCP, unix and `endpoint=NAME` ends, also through `--via` | **Wire-unified, both directions** (#145). A Rust host does not offer named endpoints (an in-page host does); the CLI reaches them. See [Forwarding with `wsh -L`](#forwarding-with-wsh--l---r---n) |
| Gateway flow control (#123) | credit per connection (`GatewayCredit`, feature `gateway-credit`); host caps for peers without it | `wsh-server` and `wsh-client`: 256 KiB per direction when both list `gateway-credit`; without it, per-connection and per-client byte caps (`max_buffered_bytes` 4 MiB, `max_client_buffered_bytes` 32 MiB) close the connection that exceeds them | **Wire-unified, negotiated**; an older peer on either side keeps working under the caps. `OpenUdp` flows are metered too (a datagram without credit is dropped) |
| TCP reverse tunnels (`ListenRequest`, #98) | `@johnhenry/wsh/server` `gateway.reverse` (off by default; loopback unless the operator lists addresses; port allow-list, nothing below 1024 unless named; bounded listeners/connections/backlog/idle); client `listenTcp(port, { onConnection })` | `wsh-server` `[gateway] enable_reverse_tunnels` + `reverse_bind_addr` (off by default, loopback, client `bind_addr` ignored); **`reverse_ports`** (default `[0, "1024-65535"]`, a list replaces it), **`reverse_max_listeners`** 4, **`reverse_max_connections_per_listener`** 16, **`reverse_backlog`** 8, **`reverse_idle_secs`** 300, with the Node host's defaults and refusal sentences (the next `rust-v` release; **breaking** for a deployment that listened below 1024 or kept a quiet tunnel for more than 5 minutes, see the CHANGELOG) | **Wire-unified** (`ListenRequest`/`ListenOk`/`ListenFail`/`InboundOpen`/`InboundAccept`; the JS host sends the real `peer_addr`/`peer_port`); **same bounds on both hosts**. Accepted connections are metered by `gateway-credit`. The Rust idle limit watches only a connection the relay is reading (one parked on the client's credit is bounded by the credit window and the caps instead) |
| UDP (`OpenUdp`) as WebTransport datagrams (#124) | `client.openUdp()` over WebTransport when both ends list `gateway-datagram`: payloads are datagrams (4-byte flow id + payload), read from `maxDatagramSize`; oversize goes on the control stream (or drops); bounds: flows, packet and byte rates, idle; policy as TCP. Host: `gateway.udp`; Playwright test from Chromium | `wsh-server` (the next `rust-v` release): the socket is `connect()`ed to the checked address, with **the same bounds as the JS host**: `udp_max_flows` 16, `udp_packets_per_second_per_flow` 500, `udp_packets_per_second_per_client` 2000, `udp_bytes_per_second_per_client` 4 MiB (both directions, `0` = no limit), `udp_idle_secs` 60 counted in both directions, on BOTH paths. **Over WebTransport it lists `gateway-datagram` in `ServerHello.features`** (`udp_datagrams`, default `true`) and, for a client that lists it too, carries the payloads as datagrams `[gateway_id u32 BE][payload]` (a datagram for an unknown flow or one that is malformed is dropped); the limit is read from the QUIC connection for every payload (`max_datagram_size`) and a payload over it goes on the control stream as `GatewayData`, or is dropped with `udp_oversize = "drop"`. A client that did not list the feature, and every WebSocket client, is served over the control stream (one `GatewayData` per datagram) exactly as before. No `gatewayStats()` counters yet (the Node host's `datagramsFromClient`, `rateDropped`, ...); drops are logged at `debug` | **Same on both hosts** (negotiated by `gateway-datagram`: a released peer on either side keeps the reliable path). Tested end to end: the JS client over a real QUIC session against the Rust binary (`test/rust/wsh-rust-server-udp-datagrams.test.mjs`) and unit tests of the framing, the policy and the bounds; **not tested**: a browser (Chromium) against the Rust server (the Playwright test runs against the Node host), and datagrams on a sealed session (WebTransport is never sealed on `wsh-server`, and the JS client sends none when it seals) |
| Gateway destination policy by resolved address | `@johnhenry/wsh/server` `gateway`: resolved address checked, `allowPrivate` | fixed in the Rust release after `rust-v0.6.0`: a loopback/private/link-local/ULA/CGNAT/unspecified/multicast address is refused after resolution unless a rule names it, and the server connects to the address it checked | **Same rule on both sides** (a Rust server released before that still has the name-only check) |
| Operator proof to the peer, sealed bridge, signed initiator half (#117) | `reverseConnect(.., { sealed, requirePeerProof })`; host `createReverseHost({ requireOperatorProof })`; relay lists `operator-proof` | **Operator proof: yes.** The Rust relay lists `operator-proof` and carries `ReverseChallenge`/`ReverseProof`/`ReverseConnect.features`; `wsh reverse-connect` answers a challenge (`--operator-proof` / `--no-operator-proof`; by default only for a peer that registered the `operator-proof` capability, because a released Rust host cannot decode the field); `wsh reverse` / `wsh agent run` challenge, verify BEFORE accepting, and take `--require-operator-proof` and `--allow-operator`. **Sealed bridge and both signed `KeyExchange` halves: yes** (`wsh reverse-connect --sealed`; a host with an identity states `e2e` / `e2e-sign` / `e2e-sealed` in its `ReverseAccept` once it has proven the operator). The exchange is byte-identical to JS (transcripts compared against vectors printed by the JS code), hybrid X25519+ML-KEM-768 negotiated exactly as JS does, X25519 when the peer lists no ML-KEM key. A host started with `--require-operator-proof` REQUIRES the sealed bridge (the JS rule): until the key exists it hears and sends nothing but the key exchange, and drops a bridge that has not sealed in 10 s; an operator that does not seal gets no answer to its plain messages. Every message that would cross the relay travels as an `EncryptedFrame` on channel 0; a plain message (wrapped or not) is dropped; **a frame that does not open (tampered, replayed, reordered) closes the bridge** (stricter than the JS host, which drops the frame and ignores the rest). Not covered: a direct or pipe-relayed connection, and `GatewayData` outside a reverse bridge (#155) | **Wire-unified, negotiated** (`ReverseConnect.features`, `operator-proof`, `e2e-sealed`); both implementations seal a reverse bridge |
| Channel binding of the login signature (#119) | `requireChannelBinding` (client and server); kinds `host`, `cert-hash`, `tls-exporter` | Kind `host`: the client binds to the proven host key (`--require-channel-binding`, and it honours `channel-binding-required`), and `wsh-server` offers it and can require it (`[server] require_channel_binding`, needs `host_key`). `cert-hash`: in the Rust client when the connection is pinned to exactly one certificate (`--cert-hash`, `ConnectConfig.cert_hash`); `tls-exporter`: not in Rust | **Wire-unified, negotiated** (`channel-binding:<kind>` features); verified against the spec's test vectors |
| Pipe relay (#118) | `@johnhenry/wsh/pipe-relay` | operator side only (#145): `wsh --via wss://relay/r/<id> user@host command...` (also `connect`, `scp`, `ls`, `sftp`, `copy-id`), or the URL as the target. The host side of a pipe is not implemented in Rust. As on a direct connection the Rust client verifies the host-key proof (`host-key` / `host-key-sig` over its own nonce) before sending a credential, pins only a proven key, and binds the login to it (channel binding `host`; `test/rust/wsh-cli-identity.test.mjs`); the pipe-relayed session itself is not sealed (see Security model). `wsh -N -L` exits non-zero when the host drops the session (#156), and the error lines show the relay and a shortened id, never the whole rendezvous id | **Deliberately a relay without wsh parsing** -- nothing to unify on the wire. `--via` keeps `user@host` as the identity: its key is recorded in `known_hosts` under `host:port` (what a direct connection uses), never under the relay's address; a URL target is recorded under the URL's own authority, i.e. the relay's. The URL is not saved to `last_session.json` (the id is a capability) |
| Execution targets (#121): `Open.target`, `FileOp.target`, `OpenEndpoint.target`, `ListTargets` / `TargetList` | host: `targets` on `createWshServer` / `createMemoryHost` (own backends and `authorize(who, { target, kind })` per target, `requireTarget`); client: `openSession({ target })`, `exec(.., { target })`, `fileOperation(.., { target })`, `openEndpoint(.., { target })`, `listTargets()` | CLI: `wsh --target NAME [user@]host [command...]` and `wsh connect` (exec and shells only; every other subcommand, `-L`/`-R`/`-N` and `--share` refuse `--target`), `wsh targets [user@]host [--json]`; the client's `open_session(SessionOpts { target })` and `list_targets()` (file and endpoint calls send no target). **A Rust host with targets: not built**: `wsh-server` states no `targets`, refuses a request that names one and answers `ListTargets` with an error | **Wire-unified, negotiated** (`targets` feature; every new field optional, never sent to a host that did not advertise it) |
| Operator-side shared folders (`--share`, #159) | host side: `onShare(name, fs, who)` on `createMemoryHost` / `createWshServer` / `createReverseHost` (the host *uses* the operator's directories; `fs` is an object of async file operations, also shaped like an `fs` backend; `fs.root` is the operator's advisory, unverified path for the share, #164). The JS client does not offer shares | CLI side: `wsh --share NAME=/abs/dir[:ro\|:rw]` offers them, with each directory's path unless `--share-hide-path` (`wsh_client::share`, `wsh-cli`'s `sharefs`: descriptor-relative, never follows a link, see [Sharing a directory](#sharing-a-directory-with-the-host-wsh---share-159)); unix only. **A Rust host that uses shares: not built** (`wsh-server` does not state `shares`) | **Wire-unified, negotiated**: the host states the feature `shares`; the client sends one `ShareOffer` after login (opcodes `0xa8` `ShareOffer`, `0xa9` `ShareRequest`, host to client, `0xaa` `ShareReply`). No change notification, no sharing over `reverse-connect` |
| Sealed session: any authenticated connection incl. gateway/endpoint data (#155) | host `sealSession: 'offer' \| 'require'` (stage b); client `connect(url, { sealSession: false \| 'auto' \| true })` (stage c) | `wsh --sealed ...` (or automatic against `e2e-session-required`) seals a direct or pipe-relayed session; `wsh-server` offers or requires it on WebSocket (`[server] seal_session = "off" \| "offer" \| "require"`, needs `host_key`; `require` refuses WebTransport, WISP tunnels and password logins; with it on, the typed rpc channels (`wsh-host`, and `wsh-fs` when `[rpc] fs_root` is set) are offered in virtual data mode, #191: stated `rpc-virtual` instead of `rpc`, riding `SessionData` inside the seal, with the same credit accounting and the same per-key capability checks as stream-mode rpc) | **Wire-unified, negotiated** (`e2e-session`, `e2e-session-required`, `KeyExchange` for the connection's session id, `EncryptedFrame` channel 0) |
| Refusal event with stable reason codes (`onRefused`, #163) | `onRefused({ reason, who, detail })` on `createMemoryHost` / `createWshServer` / `createReverseHost`; `REFUSAL_REASONS` from `@johnhenry/wsh/host` | none: `wsh-server` and `wsh reverse` log a refusal, they have no callback (an embedding process has none) | **JS-only** -- a host-side callback of the embedding API, no wire change |
| `AuthOk.ttl` enforced, `token` opaque (#125) | `connectionTtlMs`; `client.authTtl` | `wsh-server` sends `ttl: 0` (no lifetime promised; `session_ttl` is the lifetime of a *detached* session) and an HMAC token that nothing accepts back | **Wire-compatible**: both fields are still sent (released peers require them). **Changed in the Rust server after `rust-v0.6.0`**: it used to send `session_ttl` (86400), which nothing enforced. The Rust client ignores `ttl` |
| `clientEnv` allow-list (#126) | default `TERM`, `COLORTERM`, `LANG`, `LANGUAGE`, `LC_*` | `wsh-server`: the same default; `[server] client_env = true` (everything, the old behaviour), `false` (nothing) or a list of names / `PREFIX*` (replaces the default) | **Both hosts**; wire unchanged. **Breaking default in the Rust server**, see the CHANGELOG |
| `authorized_keys` options (#122): `restrict`, `permit-*`, `no-pty`, `command=`, `max-sessions=` | `auth.authorizedKeys` lines with options on `createWshServer` / `createMemoryHost`; `parseAuthorizedKeyEntries()` | `wsh-server` reads `~/.wsh/authorized_keys` (then `~/.ssh/authorized_keys`) | **Same rules and the same vectors on both hosts** (`spec/key-options.vectors.json`, run by the JS suite and a Rust test); an option that is not understood keeps the key out, on both. See [Authorized-key options](#authorized-key-options-122) for the per-host column |
| Per-key capabilities and expiry (#122): `capabilities="..."`, `expires="..."`; `authorize()` may return a set | every entry the host has: `Open` kinds, `FileOp` read vs write, gateway TCP/UDP/unix/endpoint open and listen, MCP discovery and calls, targets, rpc channels, relay; refusals through `onRefused` (`not-permitted`, `key-expired`) | the same, except **no endpoints and no targets** (`endpoint:` / `target:` parse and grant nothing; such requests are refused); refusals are logged, there is no callback; no `authorize` | **Same grammar, same vectors, same refusal codes on both hosts**; default-deny only for a key whose line has `capabilities`. Neither covers sessions already open, see [Security model](#security-model). The notation is written in `spec/capabilities.md` and its vectors (`spec/capabilities.vectors.json`, `version` 1) ship in the npm package and are run by both; the Rust server's subset is stated by refusal: a key line with an `objects:` capability is refused at load (`unknown-capability`) |
| A session over a caller-supplied duplex (#220): `serveWshOverDuplex`, `connectWshOverDuplex` from `@johnhenry/wsh/duplex` | exported, browser-safe; sealed by default | none: the Rust server and client dial a WebSocket, TLS or a pipe relay (a pipe relay carries the same bytes) | **Unified on the wire** (nothing new); the binding is the JS implementation's |
| `permits(capabilities, request)`, `@johnhenry/wsh/identity` (fingerprint, pod id, OpenSSH line, `authorized_keys` line builder), the `GATEWAY_FAIL` table, `serveMcpOverDuplex`, `createDuplexPeer({ who, permit })` (#220) | exported pure functions and seams of the JS package, browser-safe | none: the Rust server and CLI export no library function of these; the Rust server sends the same `GatewayFail` numbers, with `5` meaning "gateway disabled"; the Node gateway sends `8` for a timeout (older Node gateways sent `5`, so a reader still takes a `5` as "disabled, or a timeout from an older Node gateway") | **Notation unified by vectors**; the functions are the JS implementation's and are not a wire feature |
| Session recording/replay | `SessionRecorder`/`SessionPlayer` (asciicast-v2-shaped JSON) | none | **JS-only** -- no current Rust consumer needs playback; the vocabulary is asciicast v2's, so a Rust port could share it |
| Self-signed cert pinning | `serverCertificateHashes` (WebTransport option) | `--cert-hash <sha256>` (repeatable) and `ConnectConfig.cert_hash`/`cert_hashes`, with the same rules (SHA-256, ECDSA P-256, at most 14 days); `wsh-server` prints its certificate hash at start-up. Without a pin the certificate is validated against the system trust store; `--insecure-skip-cert-verification` is the development-only opt-out | **Not a wire concept**; a default changed in the Rust client, see the CHANGELOG |

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

`wsh --version` and `wsh-server --version` print the workspace version the binary was built from (`wsh 0.18.0`), which is the
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

- **A page host (`@johnhenry/wsh/page`, #190) lets a remote key call the page's allow-listed WebMCP tools, and nothing else.** What it narrows
  (key login, sealed session, an allow-list by tool name, the key's `mcp:TOOL` capabilities, the person's approval for consequential tools,
  bounds, a visible Stop) and what it cannot make safe (a tool does whatever its `execute` does with the user's session; results may carry
  third-party text and are untrusted to the MCP client; the dialog and the indicator belong to the page and are not a defence against code
  already in it; a fresh host key per page load means no pin outlives it unless `hostKeyStore` is given) are stated in
  [A page as a host](#a-page-as-a-host-johnhenrywshpage-190). The **dial-out form** (`connect`, off unless written) makes the page dial an endpoint of the embedder's choosing:
  the page does not authenticate that endpoint (the operator pins the page's host key, the page checks keys), the endpoint learns the host key and the stated features before
  any login, and the page redials it while the host is open; the URL is not logged. The key login, sealing, approval, indicator and Stop are unchanged.
- **Objects and MCP over a transport that is not wsh (`createDuplexPeer`, `serveMcpOverDuplex`, #220) are only as authenticated as that transport.** The
  identity they hand to `authorize(who, op)`, a prompt and `onCall` is whatever the adapter gave (`who`, `permit`, `permits`): `fingerprint` and `podId`
  are checked to agree, nothing else is verified, and the messages carry no proof of either. They bound what they receive (message size, requests in
  flight, one answer per id), refuse what is not the protocol, and fail closed when a `permit` throws or answers anything but `true`; they do not seal, and
  a hop that can read the duplex reads every tool result and every value. The capability notation (`spec/capabilities.md`) is a **reading** of a list, not a
  credential: an implementation that reads it more loosely than the vectors say grants more than the list does, which is why the vectors are shipped.
- **`wsh-objects` (`@johnhenry/wsh/objects`, #190) lets a key read, call and set the paths an allow-list names on the roots a host names, and nothing else.** An allow-list of paths means what it says
  only because nothing but cloneable values crosses (no handles in `values` mode; on a root that opted in to [handles](#handles), a handle is judged by the path that produced it and never widens it, and nodes need their own opt-in; an event subscription through a handle needs the producing path's own `allow.on` entry and ends with the handle); what it cannot make safe is stated in
  [Remote objects](#remote-objects-johnhenrywshobjects-190): a getter or a setter on an allowed path runs, a called function does whatever it does with the page's authority, a wide pattern means its width, and a
  few paths (`document.cookie`, storage, `fetch`, ...) need an entry that names them. A callback that returns a value (`(callback:returns)`) is not a way for the far side to call into the page more widely, but it is a way for the far side to make the page wait: that wait is bounded by the host (`callbackReturnTimeoutMs`, at most 30 s, and `maxPendingCallbackReturns` waiting calls per channel), and nothing the far side answers is more than plain data; it does not protect a page whose own code trusts the answer. The generated types (#219) are advisory text: the host's type map is host-authored text that is checked, bounded and never evaluated (see [Typed remotes](#typed-remotes-219)), and the file says only what the fetching key may do. The MCP face for named paths (#219) is the allow-list **plus** a list of the paths that are tools, **plus** the WebMCP bridge's approval for any tool not marked read-only: a tool needs the key's `mcp:TOOL` and `objects:ROOT:OP`, its arguments are validated before the person is asked, its results are labelled untrusted, and it makes no handle, event or callback; a called function still does whatever it does with the page's authority. Object access is off on every host unless `exposeObjects` or `createPageHost({ expose })` is written, and `rpc:wsh-objects` is the key capability that gates it. The Rust client (`wsh objects`, `wsh_client::objects`) is only as safe as the host it speaks to: a callback it passes lets the host's code push plain values at the process (bounded by its own queue and the host's rate and size limits; they are text from the host and are escaped in `wsh objects session` output, never interpreted), a subscription through a handle lives only as long as the handle, and `types` prints text the host wrote. None of it widens what the host's allow-lists and the key's capabilities allow.
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
  same (loopback, off, ports `0` and `1024-65535`, 4 listeners per client, 16 connections per listener, a backlog of
  8, a 5-minute idle limit): `reverse_ports`, `reverse_max_listeners`, `reverse_max_connections_per_listener`,
  `reverse_backlog` and `reverse_idle_secs` under `[gateway]`; the same applies to its UDP flows (`udp_*`).
- **UDP is not authenticated or private beyond the tunnel.** `allow: ['*']` with a public resolver lets every authorized
  client send UDP to the internet from the host's address (a DNS-sized query, or a spoofed-looking flood limited only by
  the packet rates above); the bounds make that slow, not impossible, and an origin that answers many large datagrams
  to one small one is bounded by `bytesPerSecondPerClient`, not eliminated. WebTransport datagrams can be dropped,
  reordered and duplicated by the network, and are only as private as the QUIC connection that carries them (a
  datagram flow is not covered by E2E sealing, which is for sessions). A payload that did not fit a datagram travels on the
  reliable stream by default (see the README section above). On the Rust server a datagram is heard only after the
  connection has authenticated, for a flow that connection opened (an unknown or malformed one is dropped), and goes
  through the same per-flow, per-client and byte limits as a payload on the control stream.

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
- **The Rust client verifies the server's WebTransport certificate, and what that does and does not protect.** By
  default the certificate must chain to the system trust store; with `--cert-hash` it must be the pinned one (no
  authority involved); only `--insecure-skip-cert-verification` skips the check, with a warning on every connection.
  Verification stops an on-path party from terminating the connection as the server. It does not prove WHICH host a
  person is talking to beyond what the certificate names (a pin proves "this certificate", and `known_hosts` /
  `--host-key` prove the host's own key, which is a separate and stronger check), it does not cover the `wss://`
  fallback's `WSH_INSECURE_LOOPBACK_TLS` development variable (which now applies to loopback destinations only: it skips
  verification when the socket connected to 127.0.0.0/8 or `::1`, judged on the address reached and not on the name, and
  for any other destination it is ignored, with one line on stderr saying so), and a pinned certificate must be re-pinned when it is
  rotated (at most every 14 days). With the opt-out, a host that proves no key is not authenticated at all.
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
  refused **after the name is resolved**, whichever rule matched the name (a host
  name rule included), unless a rule names that address or range
  (`"10.1.0.0/16:5432"`, `"127.0.0.1:8080"`; a literal address is matched when a
  client asks for that address, a range also when a name resolves into it). The server connects to the address it
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

- **A rule you write is trusted, as far as it says.** A hostname rule
  (`"partner.example.com"`) allows that name at a public address only, as the wildcard
  does: a name whose DNS answers an internal address is refused, so a name is not
  how the internal network is reached. An address range or literal address rule
  allows exactly what it says, so write `"10.1.2.3/32:5432"` to let `db.internal`
  resolve to that one address. It does not protect against a public address that
  forwards to something internal (a proxy, or a service you allow that fetches URLs).
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
  and the rest of browsermesh meets wsh in several places (see [wsh and browsermesh](#wsh-and-browsermesh)).
- **The Rust crates** in [`crates/`](crates) (`wsh-core`, `wsh-client`, `wsh-cli`, `wsh-server`) are a native
  implementation of the same wire protocol, versioned separately (`rust-v*` tags) and generated from the same
  `spec/wsh-v1.yaml`; see [Rust implementation](#rust-implementation) for what each side can do.
- **[clawser](https://github.com/erisera-code/clawser)** downloads the Rust release binaries by their archive names and is
  where the Rust workspace came from.

## wsh and browsermesh

**wsh** is the authenticated, capability-scoped door into **one machine or one page**: a key login in both directions, a host key a dialler
can pin, a session sealed end to end, and what a key may do written down as capabilities. **[browsermesh](https://github.com/johnhenry/browsermesh)**
is the **peer fabric**: pods that find each other, link, route messages and share state, with no machine at the centre. One is a way
into a place; the other is the place between places. They are separate packages with separate versions, and **wsh has no dependency on
browsermesh** (a test of the pod id derivation uses `@johnhenry/browsermesh-primitives` as a dev dependency only).

**Where they meet**

- **The mesh's wsh peer link** (`@johnhenry/browsermesh-transport`, off by default): a link between two pods is one wsh session, sealed and
  authenticated in both directions, carrying one named endpoint (`mesh`) on which the mesh's frames travel. A pod's Ed25519 key is its wsh
  login; the pod id it claims must equal the hash of the key wsh authenticated. wsh supplies the session (login, host key, seal, endpoints);
  the mesh supplies the frames. `@johnhenry/wsh/identity` is where the pod id and the fingerprint convert.
- **The relay's pipe route**: browsermesh's relay server serves wsh's [pipe relay](#a-pipe-relay-johnhenrywshpipe-relay-118) (rendezvous and
  byte copying, no keys), so two pods that cannot reach each other directly still run the ordinary wsh handshake end to end. `@johnhenry/wsh/testing`
  has the same relay in process, with a tap for a hostile one, as a test double.
- **netway's gateway backend** (`@johnhenry/browsermesh-netway`): its `GatewayBackend` takes a `WshClient` and proxies every network
  operation through the host's [gateway](#gateway-tcp-and-dns-egress-from-the-host); it decodes the `GatewayFail` codes of
  `GATEWAY_FAIL` / `GATEWAY_FAIL_TABLE`, exported here as data so there is one table.
- **Objects and MCP over a mesh channel**, through the browsermesh adapter package (a separate, small package that peer-depends on
  `@johnhenry/wsh`): a page's [remote objects](#remote-objects-johnhenrywshobjects-190) and WebMCP tools reachable over a protocol channel
  with no wsh relay. wsh exports the seams it needs: `createDuplexPeer({ send, who, permit })` and `createObjectsServer(...).attach` for objects,
  `serveMcpOverDuplex` for MCP, the identity object `{ username, fingerprint, podId }`, and `permits()` of the
  [capability notation](#identity-and-capabilities-for-other-implementations-220), which the mesh's own grants run the same vectors against.

#### wsh over a duplex (#220)

`@johnhenry/wsh/duplex` runs a whole wsh session (login, host-key proof, sealed session, channels) over a duplex of messages that another library
provides, so a browser with no relay can be reached by hopping through a mesh peer, and a pod can reach a wsh host without a relay. The transport
is the one wsh already runs over a WebSocket; `createDuplexSocket` is a WebSocket-shaped object whose messages are the duplex's.

```js
// host (a page, a pod): a host with a host key
const host = createMemoryHost({ auth: { authorizedKeys }, hostKey: true, dataStreams: false, exec });
const served = serveWshOverDuplex(host, { send: (bytes) => channel.send(bytes) });
channel.onmessage = (bytes) => served.receive(bytes);
// client: it names the host key it expects (over a mesh: podIdToFingerprint(peerPodId))
const link = connectWshOverDuplex({ send: (bytes) => channel.send(bytes) }, { username, keyPair, expectHostKey });
channel.onmessage = (bytes) => link.receive(bytes);
const client = await link.connected;
```

**The duplex must** deliver messages of bytes reliably and in order, with a maximum size both ends know (`maxMessageBytes`, default 64 KiB; a larger
write is cut, a larger incoming message ends the link), and apply backpressure by `send` returning a promise (what waits is bounded by
`maxBufferedBytes`, default 4 MiB). One duplex carries one session. The full statement is [`spec/duplex-binding.md`](spec/duplex-binding.md).

**Channel binding here is not TLS's.** There is none of `cert-hash` or `tls-exporter`. The authentication is carried by the host-key proof (the client
compares the key with the one it named), the login bound to that key (`requireChannelBinding: ['host']`, the default) and the sealed session. So a hop on
the duplex cannot read or change a command, an output or a credential after login, cannot replay one, and cannot answer as the host to a client that named
its key. It can see that a session exists, its timing and sizes, and the plain handshake (the host key, the username, the client's public key); it can
drop or delay (the session stalls) or end the link. It is **not** protected against: a client that does not name the host key (`trustOnFirstUse: true` is
said out loud: the first answer is trusted), a **password** login (sent before the seal; refused unless `allowUnsealed: true`), or what the host's own
`auth` and capabilities allow. **Unsealed is refused by default**: the host serves a duplex only sealed (it needs a host key; `sealSession: 'require'`
can now be asked of one connection, `host.accept(socket, { sealSession: 'require' })`, and only strengthens the host's setting), and the client
refuses a host that cannot seal. `allowUnsealed: true` on either lifts it, and then a hop can read and change everything.

**What is deliberately not shared**

- **Sealing.** A wsh session is sealed once, after a signed key exchange, and everything after login travels in authenticated frames; the
  mesh seals one-shot routed messages in its own way. They are two schemes for two shapes of traffic, and neither is built on the other.
- **Wire codecs and addressing.** wsh speaks CBOR messages over QMux (WebSocket or WebTransport streams) and is reached by a URL or a rendezvous
  id; the mesh has its own encodings and names pods by id. Neither adopts the other's.
- **Exec and hosted pods.** Shells, commands, files and the gateway are wsh's; running things for other pods and hosting them is the mesh's.
  Discovery and state sync stay in the mesh.
- **Machine rights from mesh trust.** Being a peer of a pod, or holding a mesh grant, never gives a key exec, files or the gateway on a
  machine. What a mesh grant can reach in a page is objects and MCP tools only, and only what that page's host opted in to.

**One key in both worlds is possible, never automatic.** A pod's key can be exported as an OpenSSH line and a key from `authorized_keys`
can be imported as a pod identity (`rawKeyToOpenSsh`, `openSshToRawKey`), explicitly. Do not do it for a key that is stored in a browser
and valid on real machines: a key that can open a shell somewhere should not also be the identity a page presents to every peer it meets.
Capabilities from the mesh are written as an `authorized_keys` line only by `authorizedKeyLine`, which refuses a line that grants
more than it was asked for.

## License

MIT
