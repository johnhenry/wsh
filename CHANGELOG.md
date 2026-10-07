# Changelog

## 0.23.1 (2026-10-07)

- **Verified and closed: stream-mode sessions invisible to the host until the client writes a
  byte (#65).** Fixed in two steps already released: 0.18.0 made the stock client's transport
  announce every stream it opens with an empty STREAM frame (`QMuxStream.announce()`) and made
  `@johnhenry/wsh/server` advertise `stream-announce` and drop a lone leading `0x00` primer; 0.23.0's
  WebTransport listener needs neither. The Rust `wsh-server` is not affected: it serves exec
  channels as `data_mode: 'virtual'` (no second stream), so it has no primer to strip. The one
  residual case, a third-party client that neither announces nor primes, cannot be solved
  host-side (nothing is on the wire) and is documented in the README's compatibility table.
- **Fixed: a zero-length `QMuxStream.write()` on a fresh stream sent nothing** and marked the
  stream as started, so a later `announce()` was a no-op and the peer still never saw the stream.
  It now announces the stream (the issue's expected behaviour); on a stream that already sent
  something it remains a no-op.
- **Tests:** an un-primed client (`primer: false`, nothing ever written) against the Node host for
  both `WshClient.exec()` and `openSession()`; QMux-level visibility (opened stream invisible,
  `announce()` and a zero-length write make it visible without any payload).
- **Docs:** `AGENTS.md` release section now describes the publish-from-main model.

## 0.23.0 (2026-10-07)

- **New: `@johnhenry/wsh/server` listens for WebTransport (#70).**
  `createWshServer({ webTransport: { port, host?, path = '/wsh', cert, privKey, selfSigned, secret? } })`
  serves HTTP/3 sessions with `@fails-components/webtransport` (imported lazily; an optional
  peer, along with `@fails-components/webtransport-transport-http3-quiche`) next to the
  WebSocket listener, with the same auth, `exec`, `pty`, `fs`, `mcp`, `sessions` and `relay`. The
  control stream is the session's first bidirectional stream (length-prefixed CBOR frames),
  later client-opened bidirectional streams bind to exec channels in `OpenOk` order, and the host
  advertises `stream-announce` (a WebTransport stream is visible when it is created, so no
  primer). `selfSigned: true` generates, with no dependency, a 13-day ECDSA P-256 certificate and
  `server.webTransport()` returns its SHA-256 (`certificateHash`) for the client's
  `serverCertificateHashes`; `generateSelfSignedCertificate()` is exported. The certificate is
  not renewed. `server.close()` closes the WebTransport sessions.
- **Fixed (client): a WebTransport session that never became ready left `wt.closed`'s
  rejection unhandled** -- fatal in Node -- on top of the `ready` rejection `connect()` already
  surfaces. The transport now observes `closed` from the start.
- **Tests:** `test/server-webtransport.test.mjs` runs the stock client over a real HTTP/3
  connection (pinned hash, `echo hello`, concurrent exec, stdin, `fileWrite`/`fileRename`, MCP,
  auth refusal, wrong pin, wrong path, shutdown) and skips with the reason where the native binary
  cannot load. No spec, codegen or Rust change.

## 0.22.0 (2026-10-07)

- **New: `@johnhenry/wsh/server` is a relay (#69).** `createWshServer({ relay: {
  canRegister, canConnect, maxPeers?, connectTimeoutMs? } })` keeps a peer table
  keyed by key fingerprint. `ReverseRegister` is checked against the connection's
  authenticated key and its self-signed record is verified (with the existing
  `verifyPeerRecord` transcript) before it is accepted; the record `seq` must
  increase per fingerprint and is remembered across reconnects. `ReverseList`
  answers only the peers the caller may connect to; `ReverseConnect` is forwarded
  with `from_fingerprint`/`username` set from the operator's authenticated login;
  `ReverseAccept`/`Reject` pair the two connections; and from then on forwardable
  messages cross as `RelayForward` with a server-set `from_fingerprint`. A
  client-written `RelayForward` is unwrapped, its inner checked against the spec's
  `forwardable` allowlist, and re-wrapped with the real sender; unbridged traffic is
  never forwarded. **Default deny**: `canRegister` and `canConnect` both default to
  refusing. One operator per peer at a time (`busy`); a bridge ends when either
  connection does, closing the other. `server.peerFingerprints()` lists who is
  registered. Without `relay`, `ReverseList` answers an empty list and
  `ReverseConnect` a `ReverseReject` instead of being ignored.
- **New: `createReverseHost({ url, username, keyPair, accept, exec, pty, fs, mcp })`**,
  the registered side: it dials out with `connectReverse()`, asks `accept` (default:
  refuse everyone) about each operator, and serves the bridged one with the same
  connection code `createWshServer` uses, over an in-memory message pipe. Exec
  sessions are `data_mode: 'virtual'` over a bridge. Redials with backoff (a relay
  closes the peer when a bridge ends); `reconnect: false` to disable.
- **Internal:** the connection factory can now attach to a message transport
  (`sendMessage` / `receiveMessage` / `bindStream`, pre-authenticated, with
  `dataStreams: false`) as well as a QMux byte pipe, and closes the socket when the
  host ends a connection itself (a refused login, an ended bridge) instead of
  leaving that to the client. Backends (`exec`/`pty`/`fs`/`mcp`) are built in one
  place shared by the server and the reverse host. No spec, codegen, Rust or client change.
- **Not provided:** E2E between operator and peer (`KeyExchange` is not on the
  `forwardable` list, so the relay sees traffic in clear); several operators per
  peer. See the README.

## 0.21.0 (2026-10-07)

- **New: `@johnhenry/wsh/server` attach / resume / detach of pty and exec
  sessions (#68).** `createWshServer({ sessions: { detachTtlMs, maxDetached,
  ringBytes, sessionSecret } })` keeps a per-server session registry that
  outlives connections: a dropped socket detaches its sessions (they keep running
  and keep filling a ring buffer of the newest `ringBytes`) until `detachTtlMs`
  elapses, `maxDetached` evicts the longest-detached, or a client resumes.
  `Resume` (token AND ownership) replays from `last_seq`; `Attach` (token OR
  ownership) replays the retained tail and supports several connections per
  session with `readOnly` viewers and `Presence` broadcasts; `Detach` and
  `SessionListRequest` are answered. Tokens use the spec's 40-byte
  `[expiry][HMAC-SHA256]` format; `sessionSecret` fixes the key across restarts.
- **Defined: `seq`.** `Resume.last_seq` is the cumulative number of session
  OUTPUT BYTES the client has received; no per-frame field was added (the client
  counts). A `last_seq` older than the ring still holds, or newer than the
  session has produced, is an error naming the gap. Documented in
  `spec/wsh-v1.yaml` (`Resume`, `AttachmentInfo`).
- **Spec (additive):** `AttachmentInfo` gains optional `channel_id` and `seq`,
  set only on the entry for the caller in the Presence that answers its own
  Attach/Resume: the channel assigned on this connection and the position of the
  first byte that will arrive on it. `AttachmentInfo` is not a
  `deny_unknown_fields` message in the Rust crates, so existing Rust peers ignore
  them; `crates/wsh-core/src/messages.gen.rs` is regenerated and the four
  `AttachmentInfo` literals in `wsh-server` set them to `None`. No Rust feature
  work: the Rust `wsh-server` still replays its whole ring on Resume.
- **New (client, additive):** `WshSession.seq` (output bytes received), and
  `attachSession()`/`resumeSession()` now resolve with the Presence plus a
  non-enumerable `session` -- a message-backed `WshSession` for the new channel --
  when the host assigns one. The existing return value and every existing call are
  unchanged.
- **Behaviour:** the host now finishes handling messages already received before
  it tears a connection down. A client's `disconnect()` sends `Close` for every
  channel and then closes the socket; that `Close` used to be dropped on the floor
  when the socket closed first. Without `sessions`, nothing observable changes
  except that `Attach`/`Resume` answer `not enabled` (and `SessionListRequest` an
  empty list) instead of being ignored until the client times out.
- Sessions are in-memory (a restart ends them), and ACL grants /
  `ControlChanged` are not built; see the README.

## 0.20.0 (2026-10-07)

- **New: `@johnhenry/wsh/server` serves MCP tools (#71).**
  `createWshServer({ mcp: { tools, client?, authorize?, maxConcurrent?,
  timeoutMs? } })` answers `McpDiscover` with the operator's tools (advertised
  with their `inputSchema` as `parameters`) and `McpCall` by validating the
  untrusted arguments against `inputSchema`, running `call(args, { user,
  fingerprint, signal })`, and replying with the call's own `call_id` (the
  server advertises `mcp-call-id`, so concurrent calls from `client.callTool()`
  / `WshMcpBridge` each get their own result, and a slow tool never blocks the
  calls behind it). Unknown or `authorize()`-hidden tools, invalid arguments,
  throwing tools, timeouts (default 30 s) and the per-connection cap (default
  8) all answer `{ success: false, error }`; in-flight calls abort on
  disconnect. `mcp.client` proxies an `@modelcontextprotocol/sdk` client's tools
  (duck-typed -- the SDK is not a dependency). The schema validator is built in
  (no runtime dependency) and refuses unsupported keywords at startup. No spec,
  codegen, Rust or client change. Without `mcp`, discovery now answers an empty
  list and a call an error result instead of being ignored.

## 0.19.1 (2026-10-06)

- **Fixed: overlapping file operations could receive each other's result
  (#72).** `fileOperation()` (and so `fileStat`/`fileRead`/`fileWrite`/
  `fileRename`/...) resolved with the next `FileResult` of any channel. It now
  matches on `channel_id`, which `FileOp` and `FileResult` already carry, so no
  wire change. It bit whenever replies arrived in a different order from the
  requests -- e.g. a multi-chunk `fileWrite` (answered after its last chunk)
  racing a `fileStat`. A host that does not echo `channel_id` on `FileResult`
  (required by the spec) would now time out where it used to work by luck.

## 0.19.0 (2026-10-06)

Closes the gaps between `@johnhenry/wsh/server` and the hosts consumers had
been vendoring. No spec, codegen or Rust change; everything new rides in
existing frames and `features` strings (see README, Node Server).

- **New: host key / TOFU.** `createWshServer({ hostKey })` (`{ file }`,
  `true`, or a `CryptoKeyPair`) populates `ServerHello.host_fingerprint` and
  proves possession of the key with a signature over a client-chosen nonce, so
  the proof cannot be replayed. The stock client surfaces it as
  `client.hostKey` / `onHostKey` and enforces `expectHostKey` (fingerprint,
  ssh line or raw key) and `knownHosts` + `trustOnFirstUse`, throwing the new
  `HostKeyError` (`HOST_KEY_MISSING | _INVALID | _MISMATCH | _UNKNOWN |
  _REJECTED`) **before any signature or password is sent**. `server.hostKey()`
  returns the advertised identity. `exec()` and `connectReverse()` take the
  same options. Pinning is not confidentiality: the proof covers the
  ServerHello, not the stream -- use `wss://`.
- **New: password auth.** `auth: { password: (user, pass) => boolean |
  Promise<boolean> }`, using the protocol's existing password `Auth` frame (no
  extension). Per-address failure throttle (`auth.rateLimit`: `maxFailures`,
  `windowMs`, `lockoutMs`, `failureDelayMs`, `key`); a locked-out caller never
  reaches the callback. Methods are independent: key-only hosts refuse
  passwords and password-only hosts refuse keys.
- **Fixed: `client.fileWrite()` and `client.fileRename()` never sent the data /
  the new path** (the `FileOp` frame has no field for either, and the client
  dropped both arguments). They now send the payload as `FileChunk` frames on
  the op's channel, gated on new host features `file-write` / `file-rename`
  (the client throws against a host without them rather than send a request
  the host would misread). The server implements both under `fs` with the same
  traversal and symlink confinement as every other op, `readOnly` and
  `maxFileBytes` honoured; `fileWrite` replaces the file or writes in place at
  an `offset`, `fileRename` refuses to overwrite, to move a directory into
  itself, or to touch the root. `upload` now also refuses non-regular files
  (a FIFO would block the host).
- **Docs:** the server README now documents the leading-`0x00` primer drop and
  a Compatibility table of announce-vs-primer behaviour for every
  client/host pairing; the stale "no server populates `host_fingerprint`"
  statements are scoped to the Rust server.
- **Tracked, not built:** server attach/resume (#68), relay/reverse (#69),
  WebTransport (#70), MCP (#71); concurrent file ops can receive each other's
  result (#72).

## 0.18.0 (2026-10-06)

- **New: `@johnhenry/wsh/server`, a Node host for the protocol.**
  `createWshServer({ host, port, auth?, exec?, pty?, fs? })` returns
  `{ listen(), close(), address() }` over `ws` (an optional peer dependency;
  the root entry is untouched and stays browser-safe). Ed25519 allowlist /
  callback auth, `exec` (child_process or a custom runner), `pty` (inject
  node-pty), and `fs` (list/stat/read/mkdir/remove, upload/download, confined
  to a root). All of exec/pty/fs are off by default; no `auth` refuses
  everyone. Distilled from the host consumers had been vendoring; not
  included: WebTransport, relay/reverse, attach/resume, MCP.
- **Fixed: exec sessions lost all output unless the client wrote a primer byte.**
  Root cause: a QMux/QUIC stream is created lazily on the wire -- opening one
  sends nothing until the first byte, and an exec client has no stdin, so a
  host that binds the data stream on first sight never saw it and dropped the
  output. `WebSocketTransport` now announces every stream it opens with an
  empty STREAM frame (`QMuxStream.announce()`), so the host sees it at once.
  The server advertises a new `stream-announce` ServerHello feature
  (`STREAM_ANNOUNCE_FEATURE`); against any other host the stock client writes
  the primer itself for stream-mode `exec` (`openSession` and `WshClient.exec`
  take `primer: false` to opt out). No wire-format or spec change.
- `sign(privateKey, message)` / `verify(publicKey, signature, message)`
  (WebCrypto order, unchanged) are now documented as the canonical form
  across wsh, raijin and browsermesh. `podId()` is not documented API and
  stays unexported.

## 0.17.1 (2026-09-26)

- **`exports["."]` gains a `types` condition; `fileList`/`fileRemove` are now
  declared (#63).** Found while building the Web Shell room of ORRERY, which
  builds a restricted host straight from the exported QMux/CBOR/auth
  primitives. Two independent gaps in `src/index.d.ts`, both invisible unless
  a real TypeScript consumer imports the package by name:
  - `package.json`'s `exports` map had no `types` condition (only a legacy
    top-level `types` field), so under Node16/NodeNext module resolution
    TypeScript reported TS7016 ("could not find a declaration file") for
    `import ... from '@johnhenry/wsh'` -- that legacy field is not consulted
    once `exports` is present under this resolution mode. `exports["."]` now
    carries `types` alongside `import`, matching the pattern already used by
    sibling `@johnhenry/*` packages that ship hand-written declarations
    (`andbox`).
  - `WshClient.fileList`/`fileRemove` are implemented and reachable at
    runtime (`fileOperation()`'s `'list'`/`'remove'` ops) but were absent
    from the class declaration entirely, so any TypeScript consumer got a
    "Property does not exist" compile error despite the methods working
    fine at runtime. Both are now declared, returning a new
    `WshFileOperationResult` type for the raw (snake_case) `FileResult` wire
    shape.

  `test/types/file-ops.ts` is a new type-only fixture, checked by a new
  `npm run typecheck` script (now also gated in CI): it imports
  `@johnhenry/wsh` by its published name and calls `fileList`/`fileRemove`,
  so a future regression in either the `exports` map or the class
  declaration fails the build instead of waiting for the next consumer to
  hit TS7016 or a missing-property error by hand.

  Also checked, per the issue, whether `MSG`'s message-type count (97) still
  matched the README (it does -- both were already at 97 by the time this
  landed); the "97 vs 95" mismatch the issue reported is in the docs site at
  opensource.johnhenry.me, which lives outside this repo and is unaffected
  by this change.

## 0.17.0 (2026-09-08)

- **`list()` now uses the structured file channel on both clients, and
  `wsh sftp`/`wsh ls` exist (#59, #58).** `WshFileTransfer.list()` ran
  `ls -la` over an exec channel and parsed text output; the Rust client had
  no `list()` at all. `FileResult.metadata` (previously untyped `json`)
  gained a typed `entries: FileEntry[]` field (name/size/modified/type,
  including symlink targets), generated into both languages, and both
  `list()` implementations now send `FileOp{op:"list"}` and read it. New
  Rust CLI commands: `wsh ls [user@]host:path` (one-shot) and
  `wsh sftp [user@]host` (interactive: ls/cd/pwd/get/put/lls/lcd/rm, plus
  `-b batchfile`), sharing `scp`'s `[user@]host:path` parser. A refusal
  (unimplemented op, no such path) now surfaces as a named error on both
  clients and in the CLI, never as an empty listing.

- **`wsh copy-id` is now a protocol message, not a shell command (#59).**
  `AuthorizedKeyAdd`/`AuthorizedKeyResult` replace the CLI's previous
  approach of building and running a remote shell script to append to
  `~/.wsh/authorized_keys` (a quoting hazard, and unreachable from any
  implementation without a shell channel). `WshClient.addAuthorizedKey()`
  is now available in both the JS SDK and the Rust client; idempotent.

- **`WshKnownHosts` (JS) and `ServerHello.host_fingerprint` (spec) (#59).**
  The browser SDK gets a TOFU host-identity store with the same
  verify/add/remove/list semantics as Rust's `KnownHosts`. The spec gains a
  formal host-identity field, distinct from `ServerHello.fingerprints`
  (which lists this server's *authorized client keys*, not its own
  identity -- a pre-existing latent mismatch this change documents but does
  not silently paper over). No `wsh-server` release populates
  `host_fingerprint` yet; see the README's Security section.

- **Breaking: `WshSession.onClose` now receives a reason (#36, #37).** The two
  paths that close a session did not agree; one settled a parked file chunk
  and one did not. `closeReason` is a new getter (`Error | null`), `onClose`
  is called with it, and both paths go through one teardown.

- **Breaking: `openFrame()` requires the expected role tag (#35).** The E2E
  nonce role tag was written on send and never checked on receive, so a peer's
  own frame could be reflected back at it and open successfully. The tag is
  now compared against the nonce, which makes the argument mandatory.

- **Fix: `initiateE2E` dropped the peer's key exchange when it arrived first
  (#33).** `#handleControl` discards a `KEY_EXCHANGE` no waiter is listening
  for, and the waiter was registered only after generating the local key pair.
  With both peers initiating at once, whichever finished key generation first
  sent into the other's blind window and that message was never repeated, so
  the loser waited the full timeout. Both round-1 and round-2 waiters are now
  registered before the awaits they were racing. This also removes
  `retryOnKnownFlake` from the tests: the stalls it retried were this bug, not
  the Node ML-KEM instability its comment described.

- **MCP calls carry a `call_id` (#32).** `McpCall`/`McpResult` had no
  correlation field and both client paths matched on message type alone, so
  two calls in flight returned each other's results with nothing in the reply
  to reveal the swap. The field is optional and negotiated via a new
  `mcp-call-id` server feature, because `McpCallPayload` is
  `deny_unknown_fields` server-side and an unsolicited id makes an older
  server reject the call. Against a server without the feature, MCP calls are
  serialised instead.

- **Fix: `index.d.ts` had drifted from the runtime barrel.**
  `MCP_CALL_ID_FEATURE` was exported and undeclared, `callId` was missing from
  the `mcpCall`/`mcpResult` option types, and `WshSession.closeReason` was
  undeclared while `onClose` was typed as taking no argument. A test now
  asserts every runtime export appears in the declarations.

- **Fix: the noble ML-KEM backend had never executed (#42).** Every assertion
  about hybrid key exchange ran against the native provider; the fallback that
  serves browsers without it was untested.

- **Fix: the keepalive recorded the pong and never acted on it (#38).**
  `pingIntervalMs` and `pongTimeoutMs` are now constructor options.

- **Fix: a failed connect left its socket open, and a broken socket skipped
  its own teardown.**

- **Fix: stop sending CBOR null for required wire fields**, and test against
  the spec rather than the implementation.

- **`WebTransport` options are passed through**, so a self-signed certificate
  can be pinned by `serverCertificateHashes`.

- **`isEd25519Supported()` is exported**, and the compatibility docs state the
  Ed25519 floor instead of omitting Safari.


- **Adopt the Rust wsh workspace (`crates/`) from clawser (#52).** The
  native Rust implementation of the wsh protocol (`wsh-core`, `wsh-client`,
  `wsh-cli`, `wsh-server`; ~28k lines) moved here from
  erisera-code/clawser's `crates/`, imported with history via `git subtree`.
  It was previously deleted from clawser by accident (2026-03-14) and
  restored there (2026-07-05) before this move; it now lives next to the
  JS client whose wire spec (`spec/wsh-v1.yaml`) it implements, rather than
  dragging a Rust toolchain and CI job into an unrelated browser-app repo.
  `spec/codegen.mjs` now writes `crates/wsh-core/src/messages.gen.rs`
  directly (`npm run codegen`, checked via `npm run codegen:check`). The
  Rust-server cross-implementation test (`test/rust/wsh-rust-server.test.mjs`,
  formerly clawser's `tools/test/wsh-rust-server.test.mjs`) moved with it,
  now driving this repo's own JS client instead of the npm package; it runs
  via `npm run test:rust`, kept out of the default `npm test` glob so
  JS-only contributors need no Rust toolchain. CI gained a `rust` job
  (`cargo build/test --workspace`, `codegen:check`, `test:rust`; clippy
  non-blocking pending a warnings cleanup) and a release workflow that
  publishes `wsh-server`/`wsh-cli` binaries for four targets on `rust-v*`
  tags. See the README's "Rust implementation" section. No npm package
  version bump.

- **Fix: `WshMcpBridge` and `WshFileTransfer.list()` were unreachable from a
  `WshClient`.** Both classes are exported from the package root and both
  document their constructor argument as "a WshClient", and both drive the
  connection through `sendControl()` plus `addControlListener()` /
  `removeControlListener()` (`list()` also needs `openStream()`). `WshClient`
  exposed none of those, so `discover()`, `call()` and `list()` all failed
  immediately with

  ```
  TypeError: this.#client.sendControl is not a function
  ```

  the first time a real client reached them. Three public methods
  unreachable while the suite was green — the same shape as 0.14.0's
  `attachSession()`/`resumeSession()`, and for the same reason: every test
  and both examples passed a hand-written stand-in, and a stand-in written
  to satisfy the caller cannot disagree with it.

  `WshClient` gains `sendControl()`, `openStream()`, `addControlListener()`
  and `removeControlListener()` — thin delegations to the transport it
  already owns and to `#handleControl`, which already sees every inbound
  control message. Listeners are dispatched *after* the RelayForward trust
  gate, so a relayed message from a peer this client has not accepted never
  reaches one, and a trusted RelayForward arrives unwrapped.

- **Fix: each bridge operation leaked a permanent `onControl` wrapper.** For
  a client whose only hook is a settable `onControl` property — which is what
  a bare `WshTransport` is — the subscription inlined in both helpers wrapped
  that property and never unwrapped it; the matching `cleanup()` handled only
  `removeControlListener` and `_controlListeners`. Measured against a real
  `WshTransport`, the frames an inbound control message traversed to reach the
  connection's own handler grew one per operation, with no ceiling: 1, 5, 20
  and 50 operations gave 5, 9, 24 and 54. Subscription now lives in
  `src/control-listener.mjs`, attaches once and detaches on cleanup, and
  restores the displaced handler only while its own wrapper is still the
  installed one — putting `prev` back unconditionally severs any subscription
  that nested inside it.

- **`WshMcpBridge`'s constructor and `WshFileTransfer.list()` now reject a
  client that cannot work**, naming the missing member, instead of failing
  later with a `TypeError` about a private field. `WshFileTransfer`'s
  constructor is unchanged: `upload()`/`download()` need nothing from the
  control channel.

- `WshFileTransfer`'s control-message timeout text changed from
  `Timeout waiting for response (30000ms)` to
  `File transfer response timed out after 30000ms`.

- New `test/helpers-against-real-client.test.mjs`: every case drives a real
  `WshClient` over a real `WshTransport` subclass through the real handshake,
  and asserts on what reached the wire. `npm test` goes 443 → 453.

<!--
The three sections below were written after the fact. They were missing
because this repository's history was re-rooted: 3abc3ff, tagged v0.16.1, is
main's ROOT commit, and the v0.14.0, v0.15.0 and v0.16.0 tags point at an
orphaned lineage that main does not contain. `git log` from main therefore
shows nothing before 0.16.1, which is why these never got written.

All three versions are published and in use (0.15.0 on 2026-08-29, 0.16.0 and
0.16.1 on 2026-08-30), so their contents are taken from the orphaned lineage,
which is what was actually released. 0.16.1 has no diff to read at all -- its
only commit is the root commit -- so its entry is reconstructed from the code
that root commit contains and from the issue it names.
-->

## 0.16.1 (2026-08-29)

- **Fix: data-stream EOF could close a stream-mode session before `EXIT`
  arrived, losing the exit code (#24).** A stream-mode session's data and
  control streams are independently multiplexed, so nothing orders them: a
  server that ends the data stream and sends `EXIT`+`CLOSE` in the same
  synchronous block can have the FIN win. `_pumpDataStream()` treated
  `done: true` as sufficient grounds to close, so `onClose` resolved while
  `EXIT` was still in flight and `onExit` never fired. Reproduced reliably
  against clawser's reference server for fast-exiting commands.

  `CLOSE` is now the authoritative close signal. On data-EOF the session
  starts a bounded `DATA_EOF_CLOSE_GRACE_MS` (300ms) timer instead of closing;
  the `CLOSE` handler clears it, so a prompt `CLOSE` short-circuits the wait
  rather than idling out the full period, and the timer remains as a fallback
  for servers that never send `CLOSE` after ending the data stream.

## 0.16.0 (2026-08-29)

- **Stream-mode sessions can be sealed (#22).** `WshSession.enableE2E()`
  previously hard-rejected stream-mode sessions; it now accepts them, reusing
  `e2e-frame.mjs`'s `sealFrame`/`openFrame` unchanged behind a new inline
  chunk-framing layer for raw byte streams.

  `src/stream-frame.mjs` (new) carries `ChunkAccumulator`, which reassembles
  `[4-byte BE length][12-byte nonce][ciphertext+tag]` chunks from
  arbitrarily-fragmented reads via a cursor-based buffer rather than repeated
  slicing, and `encodeChunk()` which builds them. `StreamTornChunkError` and
  `StreamAuthenticationError` distinguish a truncated stream from a failed
  AEAD check.

  Adds write coalescing: `WriteCoalescer` batches small writes on a byte and
  timer threshold derived from the session `kind` — pty favours latency, exec
  favours throughput — with an `enableE2E(key, { coalesce })` override and
  `coalesce: false` to disable.

## 0.15.0 (2026-08-29)

- **EncryptedFrame AEAD sealing, wired into virtual-mode sessions (#21).**
  Adds `src/e2e-frame.mjs` (`sealFrame`/`openFrame` over AES-256-GCM, matching
  the key `initiateE2E()` already derives), an opt-in
  `WshSession.enableE2E(sharedSecret, { role })` that seals `write()` output
  into `EncryptedFrame` and opens incoming ones into `onData`, and
  `WshVirtualSessionBackend.writeEncrypted()` to send them.

  Nonces are an 8-byte big-endian monotonic counter plus a 4-byte per-role
  tag, so the two peers of a session cannot collide. `session_id` is bound as
  AEAD additional data, so a relay cannot splice ciphertext across sessions.
  Incoming frames must match the exact next expected counter; replay and
  reorder are rejected outright.

  Adds the `channel_id` field `EncryptedFrame`'s spec was missing for routing
  to a session, regenerated via `spec/codegen.mjs`.

- **Docs brought current** with the 0.8.0-0.14.0 protocol modernization
  (README, type declarations, examples).

## 0.14.0 (2026-08-28)

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

## 0.13.0 (2026-08-27)

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

## 0.10.0 (2026-08-27)

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

## 0.9.0 (2026-08-27)

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

## 0.8.0 (2026-08-27)

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

## 0.7.0 (2026-08-27)

- **New exports**: `WS_FRAME_TYPE` (the WebSocket transport's mux
  frame-type byte values -- `CONTROL`/`DATA`/`OPEN_STREAM`/`CLOSE_STREAM`
  -- previously module-private) and `dispatchSerially`/`SerialQueue`
  (the 0.5.0 dispatch-ordering primitives, previously only used
  internally). Both are useful to anything outside this package that
  needs to speak the wire protocol correctly or reuse the same
  ordering-safety pattern -- most concretely, a from-scratch
  implementation of this transport in another runtime.

## 0.6.0 (2026-08-27)

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

## 0.5.0 (2026-08-27)

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

## 0.4.0 (2026-08-27)

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

## 0.3.0 (2026-08-27)

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

## 0.2.0 (2026-08-27)

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

## 0.0.0 (2026-08-24)

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
