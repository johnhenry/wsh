# Changelog

## 0.14.0

- **Fix: `attachSession()`/`resumeSession()` were both unreachable** (clawser
  #48). Two independent bugs, found together while wiring a real two-party
  Attach test against the Rust `wsh-server`:
  - `attachSession()` sent this connection's own AUTH-level token (from
    AUTH_OK, bound to *this connection's* auth session_id) as if it were a
    credential for the *target* PTY/exec session_id -- it never could be,
    since those are different session_ids entirely, and no code path ever
    minted a token scoped to a PTY/exec session_id in the first place.
  - Independent of the token: `attachSession()`/`resumeSession()` waited on
    `OPEN_OK`/`OPEN_FAIL` (`resumeSession()` even waited on `AUTH_OK`/
    `AUTH_FAIL`), but the server actually replies to `Attach`/`Resume` with
    `PRESENCE` (success) or `ERROR` (failure) -- both calls would have hung
    until timeout even with a valid token.
  - `OpenOk` gained optional `session_id`/`token` fields: the server now
    mints a session-scoped token when a pty/exec session is created and
    returns both alongside the channel_id, so the opener has a real
    credential to hand to a later `resumeSession()` call. Exposed on
    `WshSession` as `sessionId`/`resumeToken`. Both are `undefined` for
    channel kinds with no Attach/Resume-able session (e.g. file channels).
  - `Attach.token` is now optional on the wire: the server accepts EITHER a
    valid token OR the caller already owning/being ACL-granted access to
    the session (`grantSessionAccess`) -- a principal who was only granted
    access via ACL never receives the session's token to begin with (only
    the opener does), so requiring it would leave that case permanently
    unreachable. `attachSession()`'s `token` option is now optional to
    match; omit it for the common ACL/ownership case, or pass one
    explicitly (e.g. `session.resumeToken`) if you have it. `Resume` keeps
    requiring its token unconditionally -- it's specifically for the
    original credentialed connection coming back, where proving that exact
    credential is the point; use `attachSession()` instead for an
    ACL-granted principal who never held it. `resumeSession()` also gained
    a `lastSeq` option (previously always sent as `undefined`, which the
    wire's `required: true` field never tolerated -- so `resumeSession()`
    could never have produced a valid `Resume` message before this fix
    either).
  - `WshClient`'s previously-private, misleadingly-named `#resumeToken`
    field (the AUTH-level token -- the actual root cause of the first bug
    above, since its name invited using it as if it were a session-resume
    credential) is renamed to `#authToken` and exposed read-only via the
    new `authToken` getter, mirroring the Rust client's `WshClient::token()`.

## 0.13.0

- **Hybrid X25519+ML-KEM-768 E2E key exchange**: `initiateE2E(sessionId,
  'X25519+ML-KEM-768')` now supports a post-quantum-hybrid mode
  alongside the existing classical `'X25519'` default. New module
  `src/mlkem.mjs` prefers the native (still experimental) WebCrypto
  `ML-KEM-768` algorithm (Node 24.7+, some browsers) so this stays a
  zero-*required*-runtime-dependency library; falls back to the new
  optional `@noble/post-quantum` dependency's pure-JS implementation
  only when native support is absent, via a dynamic import. Hybrid mode
  adds one one-way message beyond classical mode's single round trip:
  after both sides exchange ephemeral X25519 + fresh ML-KEM-768 public
  keys, each independently derives the same encapsulator/decapsulator
  role assignment by comparing the two X25519 public keys
  byte-lexicographically (no extra round trip needed for role
  negotiation), the encapsulator sends the ML-KEM-768 ciphertext, and
  both combine the X25519 ECDH output with the ML-KEM-768 shared secret
  via HKDF-SHA256. Falls back to classical automatically if the peer
  doesn't support hybrid mode (algorithm agility, not a hard cutover) --
  check the returned `hybrid` flag. `KeyExchange`'s spec gained optional
  `kem_public_key`/`kem_ciphertext` fields and `public_key` became
  optional (omitted on the hybrid-only ciphertext-carrying message).
  This extends the existing `initiateE2E()`/`KeyExchange` primitive,
  which remains experimental and not yet wired to any actual
  `EncryptedFrame` encryption (unchanged from before this release --
  see the spec's e2e section note).

## 0.12.0

- **Breaking: signed peer records for reverse-mode registration** (libp2p
  RFC 0002/0003 pattern) — closes an impersonation surface where a relay
  server had no way to distinguish a peer's honest `ReverseRegister`
  fields from a forged or relay-tampered one. `ReverseRegister` gained
  two required fields, `seq` (the peer's own monotonic counter --
  `Date.now()` in practice) and `record_signature`: the peer signs a
  domain-separated transcript of its own registration fields
  (`buildPeerRecordTranscript`/`signPeerRecord` in `auth.mjs`, a
  distinct signing domain from the auth-challenge transcript even
  though both use the same Ed25519 identity key). `PeerInfo` gained
  matching `public_key`/`seq`/`record_signature` fields so operators
  can verify a peer's record themselves, independent of trusting the
  relay. `WshClient.connectReverse()` signs automatically;
  `WshClient.listPeers()` now verifies each returned entry and adds a
  non-wire `verified: boolean` field. New exports:
  `buildPeerRecordTranscript`, `signPeerRecord`, `verifyPeerRecord`.

## 0.11.0

- **Breaking: replaced the hand-rolled 5-byte WebSocket mux with QMux**
  (draft-ietf-quic-qmux-02) — QUIC-v1 frame encoding (STREAM,
  RESET_STREAM, STOP_SENDING, MAX_DATA/MAX_STREAM_DATA/MAX_STREAMS,
  DATA_BLOCKED/STREAM_DATA_BLOCKED/STREAMS_BLOCKED, CONNECTION_CLOSE,
  DATAGRAM, and a `QX_TRANSPORT_PARAMETERS` handshake frame) running
  directly over the existing reliable, ordered WebSocket byte stream.
  New modules `src/qmux.mjs` (wire codec) and `src/qmux-connection.mjs`
  (stream state machine + windowed flow control, real backpressure
  where the old mux had none). `WebSocketTransport` (`src/
  transport-ws.mjs`) now speaks QMux end to end: the control channel is
  QMux stream 0 rather than a bare `[type][stream_id]`-prefixed frame.
  Also adopts **RESET_STREAM_AT** (draft-ietf-quic-reliable-stream-
  reset-09) for reliable-prefix stream cancellation. wsh has exactly
  one consumer (clawser) and both its client and server move together,
  so this is a breaking wire change shipped in place rather than a
  parallel protocol version — no dual-version negotiation exists or is
  planned. `WS_FRAME_TYPE` is kept exported from `transport-ws.mjs` as
  a deprecated, now-unused constant for source compatibility.
- **New exports for building alternate server implementations**:
  `QMuxConnection`, `QMUX_DEFAULTS`, `QMUX_ERROR_CODE`,
  `QMUX_STREAM_INITIATOR`, `firstBidiStreamId`, `nextBidiStreamId`,
  `isClientInitiated`, `isBidirectional` — previously QMux's wire
  primitives were internal-only, forcing any non-`WebSocketTransport`
  server (e.g. clawser's Node `tools/wsh-server.mjs`, a from-scratch
  reimplementation of the protocol server side) to either depend on
  unexported internals or reimplement the whole mux by hand.

## 0.10.0

- **New `WshClient` methods closing a JS/Rust parity gap**:
  `detach(sessionId)`, `listRemoteSessions()`, `grantSessionAccess(sessionId,
  principal, permissions)`, `revokeSessionAccess(sessionId, principal,
  reason)`. These wrap `Detach`/`SessionListRequest`/`SessionGrant`/
  `SessionRevoke`, which the Rust client/CLI (`wsh detach`, `wsh
  sessions`) has supported for a while but the JS client had no
  equivalent for. `listRemoteSessions()` is a server round trip and is
  distinct from the existing purely-local `listSessions()`. Verified
  against both a mock transport and the real Rust `wsh-server`.
- **Spec accuracy fixes, no functional change**: the `EncryptedFrame`
  message's description said ChaCha20-Poly1305, but the only real
  implementation (`WshClient.initiateE2E()`) derives an AES-256-GCM key
  — the spec now says AES-256-GCM, matching the code and clawser's own
  prior design docs, and chosen because it's natively supported by
  `SubtleCrypto` in every shipping browser (ChaCha20-Poly1305 isn't, and
  this library has zero runtime dependencies by design). The `e2e` and
  `scaling` (`NodeAnnounce`/`NodeRedirect`) message families, and
  `Snapshot`, are now explicitly documented as experimental/incomplete
  in the spec — they're declared and partially plumbed (KeyExchange
  performs a real handshake; NodeAnnounce/Snapshot are received and
  logged server-side) but don't actually do the thing their names
  imply (no frame is ever encrypted, no routing decision ever made, no
  recording event ever written). Nothing to fix in code for these three
  yet — this just stops the spec from overclaiming what's implemented.
- **Removed dead code**: `#openResolvers`/`#rejectAllOpens` in
  `transport-ws.mjs` — vestigial from an earlier open-stream-ack design
  that `_doOpenStream` (which has resolved synchronously for a while)
  no longer uses; the map was always empty.

## 0.9.0

- **Unify file transfer onto FileChunk control messages (breaking).**
  Consolidates the three incompatible file-transfer schemes this
  library and its consumers had accumulated: `WshClient.upload`/
  `download`'s raw-stream length-prefixed header, `WshFileTransfer`'s
  dead ad-hoc `Open.path`/`Open.size` fields (unreachable in practice,
  and would break instantly against a Rust `deny_unknown_fields`
  server the moment they were exercised), and the spec's already-
  declared-but-fully-dead `FileChunk` message. `FileChunk` is now the
  single wire scheme, chosen because it travels as an ordinary
  control-channel message rather than raw stream bytes -- it works
  identically whether a channel's `data_mode` is stream- or virtual-
  backed, so it never depends on a real second multiplexed stream
  (which no server in this ecosystem implements).
  - `FileChunk` gains a required `total_size` field so a truncated
    transfer (channel closes before an `is_final` chunk reaches
    `total_size`) is detectable rather than silently returned as a
    short file. Added to the `relay.forwardable` allowlist along with
    `FileResult`.
  - `WshClient.upload`/`download` rewritten to send/receive `FileChunk`
    messages; `download()` gains `onProgress`/`timeout` options for
    parity with `upload()`.
  - `WshFileTransfer`'s dead ad-hoc-`Open`-fields fallback removed;
    `upload()`/`download()` now always delegate to the client.
- **Fixed a dispatch-ordering bug** that could silently drop the first
  byte(s) of a download (or any channel-scoped message arriving in the
  same batch as `OPEN_OK`): `openSession()` used to register the
  session in `WshClient`'s internal session map only as a microtask
  continuation of its `OPEN_OK` waiter -- two hops removed from message
  dispatch -- so a server that pushes channel-scoped data immediately
  after `OPEN_OK` (exactly what a fast `download()` response does)
  could have that data dispatched before the session existed to receive
  it. `OPEN_OK`/`OPEN_FAIL` are now handled as a dedicated case in the
  client's control-message dispatch that constructs and registers the
  session synchronously, in the same dispatch step as `OPEN_OK` itself.

## 0.8.0

- **Relay-forward sender identity + unified allowlist (breaking).**
  Relay-forwarded traffic previously carried no sender identity at all,
  and the client/server "which message types may be relay-forwarded"
  allowlists had drifted out of sync (hand-maintained separately, 19 vs
  21 opcodes). Fixes:
  - `ReverseConnect` gains a required `from_fingerprint` field, filled by
    the relay server from the requester's authenticated identity — never
    trust a client-supplied value.
  - New `RelayForward` message (`0x56`) wraps traffic the relay forwards
    over an established reverse connection (`Open`, `Close`, `McpCall`,
    `SessionData`, etc.) in `{from_fingerprint, inner}`, where
    `from_fingerprint` is set by the relay server and `inner` is the
    complete CBOR-encoded envelope bytes of the forwarded message.
  - New top-level `relay.forwardable` list in `spec/wsh-v1.yaml` is now
    the single source of truth for which message types may be relay
    forwarded, generated into a JS `RELAY_FORWARDABLE` Set +
    `isRelayForwardable()` and a Rust `is_relay_forwardable()`.
  - `WshClient` now tracks accepted relay-bridge peers (`trustRelayPeer`/
    `untrustRelayPeer`) and only unwraps + delivers a `RelayForward` if
    its `from_fingerprint` is a peer the app has actually accepted a
    bridge with, and the decoded inner message's type is on the
    allowlist. `reverseConnect()` trusts the target automatically on
    `ReverseAccept`; apps handling incoming `ReverseConnect` should call
    `trustRelayPeer(msg.from_fingerprint)` once they accept.

## 0.7.0

- **New exports**: `WS_FRAME_TYPE` (the WebSocket transport's mux
  frame-type byte values -- `CONTROL`/`DATA`/`OPEN_STREAM`/`CLOSE_STREAM`
  -- previously module-private) and `dispatchSerially`/`SerialQueue`
  (the 0.5.0 dispatch-ordering primitives, previously only used
  internally). Both are useful to anything outside this package that
  needs to speak the wire protocol correctly or reuse the same
  ordering-safety pattern -- most concretely, a from-scratch
  implementation of this transport in another runtime.

## 0.6.0

- **Removed `WsData`, resolving the `0x60` opcode collision with
  `Detach`.** `WsData` (`messages.framing`) was dead: never constructed
  in real code, never sent as an actual frame, explicitly excluded from
  the Rust message enum, with empty fields. Rather than move it to a new
  opcode, removed it outright -- it was cruft that caused a real bug (a
  95-key/94-unique-value `MSG` map, with `MSG_NAMES[0x60]` silently
  resolving to whichever of `Detach`/`WsData` happened to iterate last),
  which a prior pass had "fixed" by documenting the collision as
  intentional instead of investigating it. `MSG` now has 94 message
  types with fully unique opcodes.
  **Breaking**: `MSG.WS_DATA` and the `wsData()` constructor no longer
  exist.

## 0.5.0

- **Fixed a second instance of the 0.3.0 dispatch race, and deduplicated
  the fix into two shared, exported primitives.** Auditing for the same
  bug shape after 0.3.0 found `WebSocketTransport#handleControlFrame`
  had it too: a single mux frame's payload can decode into more than one
  protocol message (the CBOR decoder is stateful/streaming), and the
  dispatch loop for those decoded messages had no yield between them —
  the same unsafe shape as the message-arrival-level race 0.3.0 fixed,
  just one layer deeper, and previously missed.
  - New exports: `dispatchSerially(items, handler)` for dispatching a
    fixed, already-available batch one at a time, and `SerialQueue`
    for items arriving incrementally via a push callback (e.g. a raw
    transport `message` event) — both documented with why a plain
    for-loop or naive queue is unsafe here. Both transports' three
    separate hand-rolled instances of this pattern (the 0.3.0 fix in
    each transport, plus this newly-found one) are now this one
    reviewed, tested implementation.
  - Both primitives `await handler(item)` rather than firing it and
    yielding separately, so a handler that's itself async (e.g. one
    that internally calls `dispatchSerially` again) is *fully* waited
    on before the next item dispatches, not just yielded past for one
    microtask tick.
  - New `test/serial-dispatch.test.mjs`: adversarial tests that
    deterministically reproduce the race shape (rather than relying on
    incidentally-timed real traffic to trigger it), so a future change
    that reintroduces a fire-and-forget dispatch loop fails a fast, direct
    test instead of surfacing as an intermittent hang.

## 0.4.0

- **`Challenge` now carries `session_id` directly.** The auth transcript's
  session-id component used to depend on message ordering: a client had
  to receive and process ServerHello before Challenge to learn the real
  session id, and the 0.3.0 dispatch-race fix addressed the specific
  failure mode that caused (a client-side message-processing race). This
  goes one step further and removes the *dependency* itself: Challenge
  is now the single source of truth for session_id, so ServerHello can
  arrive in any order, be dropped, or be skipped entirely by a server
  with zero effect on transcript correctness. `WshClient` no longer
  synthesizes a session id under any circumstance -- it's always exactly
  what the server sent in Challenge.
  **Breaking**: `Challenge.session_id` is now a required field; servers
  must supply it.

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
