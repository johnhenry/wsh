# wsh-upon-star

Browser-native remote command execution over WebTransport/WebSocket with Ed25519 authentication.

wsh-upon-star is a pure-JS client library that connects browsers to remote shells. It implements its own binary protocol (CBOR over length-prefixed frames) with Ed25519 challenge-response auth, channel multiplexing, session management, and MCP tool bridging.

## Install

```bash
npm install wsh-upon-star
```

Or via CDN:

```html
<script type="module">
  import { WshClient, generateKeyPair } from 'https://esm.sh/wsh-upon-star';
</script>
```

## Features

- **Ed25519 authentication** -- challenge-response via Web Crypto API, SSH key format support
- **Dual transport** -- WebTransport (native streams) and WebSocket (multiplexed virtual streams) with identical API
- **CBOR encoding** -- compact binary wire format with length-prefixed framing
- **Session management** -- open, attach, resume, detach, rename PTY/exec sessions
- **Reverse mode** -- register as a peer and accept incoming connections through a relay
- **File transfer** -- scp-like upload/download over dedicated streams in 64KB chunks
- **MCP bridge** -- discover and invoke remote MCP tools through the control channel
- **Session recording** -- asciicast v2 compatible recording and playback with seek/pause/resume
- **Key management** -- IndexedDB storage with OPFS encrypted backup (PBKDF2 + AES-256-GCM)
- **80+ message types** -- handshake, channel, gateway, guest sharing, compression negotiation, copilot, policy, and more

## Quick Start

```js
import { WshClient, generateKeyPair } from 'wsh-upon-star';

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
import { WshClient, generateKeyPair } from 'wsh-upon-star';

const keyPair = await generateKeyPair(true);
const { stdout, exitCode } = await WshClient.exec(
  'wss://shell.example.com',
  'ls -la /tmp',
  { username: 'alice', keyPair }
);

console.log(new TextDecoder().decode(stdout));
console.log('Exit code:', exitCode);
```

## API Overview

### Core Classes

| Class | Description |
|-------|-------------|
| `WshClient` | Full lifecycle client: connect, auth, sessions, reverse mode, MCP |
| `WshSession` | Single PTY or exec channel with read/write/resize/signal |
| `WshTransport` | Abstract transport base class |
| `WebTransportTransport` | WebTransport implementation (native streams) |
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
| `fingerprint()` | SHA-256 hex fingerprint of a public key |

### Protocol

| Export | Description |
|--------|-------------|
| `MSG` | 80+ message type constants (hex opcodes) |
| `CHANNEL_KIND` | Channel types: `pty`, `exec`, `meta`, `file`, `tcp`, `udp`, `job` |
| `AUTH_METHOD` | Auth methods: `pubkey`, `password` |
| `cborEncode` / `cborDecode` | CBOR codec (maps, arrays, strings, ints, bytes, bools, null, floats) |
| `frameEncode` / `FrameDecoder` | 4-byte big-endian length-prefixed framing |

## Protocol Specification

The `spec/` directory contains the protocol definition:

- `wsh-v1.yaml` -- machine-readable protocol schema
- `wsh-v1.md` -- human-readable protocol specification
- `codegen.mjs` -- generates `messages.gen.mjs` from the YAML spec

## Browser Compatibility

Requires a browser (or Node.js 20+) with:

- Web Crypto API with Ed25519 support
- WebSocket (all browsers)
- WebTransport (Chrome 97+, Edge 97+, Firefox 114+)
- TextEncoder/TextDecoder
- ReadableStream/WritableStream

## License

MIT
