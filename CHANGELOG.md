# Changelog

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
