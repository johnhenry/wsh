# Changelog

## 0.3.0

- **Fixed a real message-dispatch race** in both transports
  (`WebSocketTransport`, `WebTransportTransport`): when several inbound
  protocol messages arrived within a single underlying read (e.g. SERVER_HELLO
  immediately followed by CHALLENGE, landing in one WebSocket `message` event
  or one QUIC stream read), they were dispatched to handlers in a tight
  synchronous loop with no yield between them. A handler that resolves a
  pending waiter (e.g. SERVER_HELLO resolving the "wait for SERVER_HELLO or
  CHALLENGE" promise) only registers its *next* waiter (for CHALLENGE) in an
  `await`'d continuation — a microtask — which never got a chance to run
  before the next message was dispatched, silently dropping it and hanging
  until timeout. Both transports now drain inbound messages one at a time
  with an `await Promise.resolve()` yield between each dispatch, letting
  FIFO microtask ordering guarantee the next waiter is registered in time.
  This is the fix for the bug that motivated servers to skip sending
  SERVER_HELLO and fall back to a shared literal session-id — servers no
  longer need that workaround against a client built from this version.

## 0.2.0

- **Security fix: the auth challenge transcript now binds `username`.**
  Previously `transcript = SHA-256("wsh-v1\0" || session_id || nonce || channelBinding)`
  never covered the username at all — a signature said nothing about which
  identity it was presented under. Now:
  `transcript = SHA-256("wsh-v1\0" || lp(username) || lp(session_id) || nonce || channelBinding)`,
  where `lp()` is a 4-byte big-endian length prefix on the two
  variable-length string fields (needed so concatenation can't collide).
  **Breaking**: `buildTranscript`/`signChallenge`/`verifyChallenge` now
  take an options object (`{ username, channelBinding }`) instead of a
  positional `channelBinding` argument.
- Fixed the codegen script (`spec/codegen.mjs`) to resolve its two-repo
  output paths correctly (JS in this repo, Rust in the companion server
  repo) instead of the stale vendored-layout paths.

## 0.0.0

- **Renamed: `wsh-upon-star` is now `@johnhenry/wsh`, restarting at 0.0.0.**
  Same library, same API — a shorter name, a new address, a new version era.
  Previously published as `wsh-upon-star` (last release 0.1.1), now
  deprecated. The GitHub repo moved to `github.com/johnhenry/wsh` (the old
  path redirects).

  ```sh
  npm install @johnhenry/wsh
  ```

  Docs: https://opensource.johnhenry.me/wsh/. The 0.0.0 is a deliberate
  restart on import, not a maturity signal.


## 0.1.0 (2026-03-15)

Initial release.

- CBOR codec with length-prefixed framing (`cborEncode`, `cborDecode`, `frameEncode`, `FrameDecoder`)
- 80+ protocol message types with typed constructors (handshake, channel, session, MCP, gateway, reverse, etc.)
- Ed25519 authentication via Web Crypto API (key generation, sign/verify, challenge-response, SSH key format)
- Transport layer: abstract `WshTransport` base, `WebTransportTransport`, `WebSocketTransport` (multiplexed virtual streams)
- `WshSession` with stream-backed and virtual (control-message) data planes
- `WshClient` with full lifecycle management: connect, authenticate, open/attach/resume sessions, reverse mode, keepalive
- `WshKeyStore` for IndexedDB key management with OPFS encrypted backup
- `WshFileTransfer` for scp-like file upload/download over dedicated streams
- `SessionRecorder` / `SessionPlayer` for asciicast v2 compatible session recording and playback
- `WshMcpBridge` for discovering and invoking remote MCP tools
- TypeScript type declarations (`index.d.ts`)
