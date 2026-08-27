# Changelog

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
