# @johnhenry/wsh

Full documentation: [opensource.johnhenry.me/wsh](https://opensource.johnhenry.me/wsh/)

> Previously published as `wsh-upon-star` (last release: 0.1.1, now deprecated).
> Renamed to `@johnhenry/wsh` and restarted at 0.0.0 on import into the
> @johnhenry family — a new name and era, not a maturity signal.

Browser-native remote command execution over WebTransport/WebSocket with Ed25519 authentication.

wsh is a pure-JS client library that connects browsers to remote shells. It implements its own binary protocol — CBOR messages over QMux-multiplexed WebSocket or native WebTransport streams — with Ed25519 challenge-response auth, session management, and MCP tool bridging.

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
- **Session recording** -- asciicast v2 compatible recording and playback with seek/pause/resume
- **Key management** -- IndexedDB storage with OPFS encrypted backup (PBKDF2 + AES-256-GCM)
- **97 message types** -- handshake, channel, gateway, guest sharing, compression negotiation, copilot, policy, authorized-key management, and more

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

// Generate an Ed25519 key pair
const keyPair = await generateKeyPair(true);

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

const keyPair = await generateKeyPair(true);
const { stdout, exitCode } = await WshClient.exec(
  'wss://shell.example.com',
  'ls -la /tmp',
  { username: 'alice', keyPair }
);

console.log(new TextDecoder().decode(stdout));
console.log('Exit code:', exitCode);
```

## Attach and Resume

Opening a PTY/exec session returns a session-scoped credential alongside the channel:

```js
session.sessionId;   // server-assigned session id (undefined for e.g. file channels)
session.resumeToken; // token minted at open time; only the opener receives it

// The original opener, reclaiming its session from a fresh connection:
await client.resumeSession(session.sessionId, session.resumeToken);

// Any other authorized principal attaches without a token -- ownership
// or an ACL grant is enough:
await client.grantSessionAccess(session.sessionId, 'bob');  // by the owner
await otherClient.attachSession(session.sessionId);         // by 'bob'

// Other session-management round trips:
await client.detach(session.sessionId);   // leave it running server-side
await client.listRemoteSessions();        // sessions this key can see
```

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
  14 days**, so it has to be reissued on a schedule.
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
| `SessionRecorder` | Record PTY I/O with timestamps (asciicast v2) |
| `SessionPlayer` | Replay recordings with original timing |
| `generateKeyPair()` | Create Ed25519 key pair via Web Crypto |
| `signChallenge()` | Build transcript + sign for auth handshake |
| `signPeerRecord()` / `verifyPeerRecord()` | Sign / verify reverse-mode peer records |
| `fingerprint()` | SHA-256 hex fingerprint of a public key |
| `parseCertificateHash()` | Decode a certificate digest from hex / base64 / bytes |
| `normalizeWebTransportOptions()` | Build a `WebTransportOptions` dictionary from loose input |

### Protocol

| Export | Description |
|--------|-------------|
| `MSG` | 97 message type constants (hex opcodes) |
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

Four crates, workspace-versioned at `0.1.0`:

| Crate | Kind | Description |
|-------|------|--------------|
| `wsh-core` | library | Shared protocol types -- CBOR messages (generated, see below), codec, identity, auth, QMux |
| `wsh-client` | library | Native Rust client -- WebTransport/WebSocket transports, sessions, file transfer, E2E |
| `wsh-cli` | binary (`wsh`) | SSH-like CLI: connect, exec, scp-style copy, reverse tunnels, key management |
| `wsh-server` | binary (`wsh-server`) | Server: WebTransport/WebSocket listener, real PTY sessions (`portable-pty`), relay/reverse-connect, WISP bridging |

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
| Host identity / TOFU | `WshKnownHosts` (localStorage-backed) | `KnownHosts`/`HostStatus` (`~/.wsh/known_hosts`-backed) | **Record unified, policy is not** (wsh #59): both pin `ServerHello.host_fingerprint`, a field no `wsh-server` release populates yet (see [Security](#security)). *When* to trust, prompt, or persist is deliberately left per-implementation -- a browser and a CLI have different UX for "first time seeing this host" |
| Interactive shell UI | none -- this SDK is a protocol client, not a terminal emulator; pair with xterm.js/ghostty-web | `wsh connect`, `wsh sftp` (line-oriented REPL) | **Deliberately not unified** -- a browser embeds a terminal widget the host page owns; a CLI process owns its own TTY |
| Reverse-connect / relay peer | `connectReverse()`, `trustRelayPeer()` | `wsh reverse`, `wsh agent` (persistent, with startup-unit install) | **Wire-unified** (registration, discovery, signed peer records); **daemonization is CLI-only** -- a browser tab cannot be a background OS service |
| Post-quantum E2E (experimental) | `initiateE2E()` (WebCrypto ML-KEM-768 or `@noble/post-quantum` fallback) | `E2eKeyExchange` (`ml-kem` crate) | **Wire-unified** algorithm and transcript; key material backends differ by platform necessity |
| Session recording/replay | `SessionRecorder`/`SessionPlayer` (asciicast v2) | none | **JS-only** -- no current Rust consumer needs playback; the format itself (asciicast v2) is not proprietary if one is added later |
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

## Security

- **Auth transcript binding** -- challenge signatures cover
  `SHA-256("wsh-v1\0" || lp(username) || lp(session_id) || nonce || channel_binding)`,
  so a signature can't be replayed against a different session or relabeled
  to a different username.
- **Signed peer records** -- reverse-mode registration is self-signed by the
  peer's identity key (the libp2p RFC 0002/0003 pattern), in a signing
  domain separate from the auth challenge. `listPeers()` verifies every
  entry client-side and reports a `verified` boolean, independent of
  trusting the relay.
- **Hybrid post-quantum E2E (experimental)** --
  `initiateE2E(sessionId, 'X25519+ML-KEM-768')` combines X25519 ECDH with
  ML-KEM-768 via HKDF-SHA256, preferring native WebCrypto ML-KEM-768 (Node
  24.7+) with the optional `@noble/post-quantum` pure-JS fallback, and
  falling back to classical X25519 automatically when the peer can't do
  hybrid (check the returned `hybrid` flag). The derived AES-256-GCM key is
  not yet wired to actual frame encryption.
- **Host identity (TOFU), and its current limit (wsh #59)** --
  `ServerHello.host_fingerprint` is the spec's formal host-identity slot:
  the SHA-256 fingerprint of a server's persistent Ed25519 host key, meant
  to be pinned across connections the way SSH pins a host key. **No
  `wsh-server` release populates this field yet** -- minting and
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

## License

MIT
