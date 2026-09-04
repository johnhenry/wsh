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
- **95 message types** -- handshake, channel, gateway, guest sharing, compression negotiation, copilot, policy, and more

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
| `MSG` | 95 message type constants (hex opcodes) |
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

## Browser Compatibility

Requires a browser (or Node.js 24+) with:

- Web Crypto API with Ed25519 support
- WebSocket (all browsers)
- WebTransport (Chrome 97+, Edge 97+, Firefox 114+)
- TextEncoder/TextDecoder
- ReadableStream/WritableStream

Hybrid ML-KEM-768 key exchange prefers native WebCrypto ML-KEM (Node 24.7+,
some browsers); elsewhere the optional `@noble/post-quantum` dependency is
loaded dynamically.

## License

MIT
