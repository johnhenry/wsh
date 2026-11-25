# Changelog

## Unreleased

### Callback return values, off unless the host opts in per entry (#219; JS)

An allow-list entry that ends in `(callback:returns)` (every function the call takes may answer) or `(callback:returns=0,2)` (only the functions at those argument positions) makes the page's stub return a **promise** of what the far side's function returned. Entries that say `(callback)` are exactly what they were: one-way, `undefined` at once.

- **The page never waits unboundedly.** The wait is bounded by the host: `limits.callbackReturnTimeoutMs` (default 2000, **at most 30000**, a larger value is a `TypeError` when the host is created), counted from the call. The promise **never rejects**; it is settled with `undefined` for a timeout, an error in the far side's function (its text stays there, in `onCallbackError`), a result that is not plain data or larger than `maxCallbackResultBytes` (16384), a call dropped by the rate or size bound, a table of `maxPendingCallbackReturns` (8, at most 64) waiting calls that is full (the call is dropped and not sent), a released callback, the end of the channel (Stop, a navigation and a revoke settle every waiting call at once and clear the timers) and a far side that did not say it can answer. `attach(...).callbackReturnStats()` counts them. A host needs `timers` for such an entry (`exposeObjects` and `createPageHost` supply them); without, it is a `TypeError`.
- **Wire (all optional, negotiated):** the string `callback-returns` in the `features` of the `roots` answer (only when an entry says it); an optional `features` list in the `roots` request (a client lists `callback-returns` to say it answers); an optional `rid` in the `callback` notification (only to a client that said it answers); one new method, `callbackResult { rid, value? | error? }`, from the far side. Documented in `spec/objects.md` section 6.
- **A released peer.** A 0.51.0 host ignores the `features` of the `roots` request, never has such an entry, and never sends a `rid`. A 0.51.0 client against a new host never listed `callback-returns`, so the host never asks it for an answer: the callback is delivered one-way and the page's promise resolves `undefined` at once (no wait). The `types` answer tells such an entry as `(callback)` so a 0.51.0 client's `rootDescription` still parses it. The Rust client (callbacks since the release after `rust-v0.18.0`) never lists `callback-returns`, so a callback it passes stays one-way, and it ignores the feature string a host states.
- **Verified in a real Chromium page** (`test/browser/page-callback-returns.spec.mjs`): the answer arrives as a promise (also from an async function, bytes included), a far-side throw or a function as the answer is `undefined`, a far side that never answers is `undefined` after the host's bound while the call itself returned at once, and Stop settles a waiting call at once with a 20 second bound.
- **README:** the Callbacks rule now says what the exception is, and the Security model says what it does not protect (a page that trusts the answer, a far side that makes the page wait up to the bound).

### Rust `wsh-objects` client: callbacks, events through a handle and `types` (#219; Rust)

The Rust client of the `wsh-objects` protocol (`wsh_client::objects`, `wsh objects`) now speaks what the JavaScript client speaks, so the three items #219 listed as "not built" in the Rust client are done. **Wire: nothing new.** Each is the existing message of the JavaScript implementation, sent only to a host that states its feature string in the `features` of its `roots` answer (`callbacks`, `handle-events`, `types`); against a host that does not (0.50.0 and earlier JavaScript hosts state no `types` or `handle-events`), the client refuses locally with `Unsupported`, naming the feature, and sends nothing. A released Rust peer (`rust-v0.18.0` and earlier, `deny_unknown_fields`) is unaffected: this changes only what the client writes to a host that said it understands it.

- **Events through a handle.** `Target::subscribe` on a `Handle::target()` sends `subscribe` with `handle` in place of `root` (host must state `events` and `handle-events`). The subscription lives as long as the handle: releasing it (or the channel ending) ends the subscription's `recv()`, and a `Subscription` keeps its handle alive while it is held. `wsh objects session`: `{"op":"watch","handle":"h1","path":"","event":"ready"}`.
- **Callbacks.** `ObjectsClient::callback(capacity)` makes a `Callback`; `Target::call_with` / `Chain::call_with` / `construct_with` pass it among the arguments (`null` at its place, `callbacks: [[index, id]]` as the host reads it; the same `Callback` is the same id; one from another channel or a released one is refused locally). The host's calls arrive one way, in a bounded queue read with `Callback::recv`: what does not fit is dropped here and counted (`dropped_here`), what the host dropped is `dropped_by_host`. `release()` (or dropping the last reference to one that was passed) sends `releaseCallback`. `wsh objects session`: `callback`, `next`, `release` and a `callbacks` list on `call` / `construct`.
- **Types.** `ObjectsClient::root_description(root)` returns the host's `types` answer as plain data; `wsh --sealed objects HOST types ROOT` prints it as JSON. Not built in Rust: the `.d.ts` generator and `Remote<T>`.
- **`wsh objects session` also gains** `types`, `watch` / `next` / `unwatch` for subscriptions (by root or by handle). Handle names stay `h1`, `h2`; callbacks are `c1`, subscriptions `s1`, each counted from 1.
- **A `wsh-objects` host in `wsh-server` is not planned**, and `spec/objects.md` section 11 says why (a Rust server has no object graph for path allow-lists to name; its typed `wsh-host` channel is the equivalent); the item is closed by that reasoning, not left open. A key line with an `objects:` capability stays refused at load there.
- Tests: unit tests of the client against a scripted host (`crates/wsh-client/src/objects/tests.rs`), and `test/rust/wsh-objects.test.mjs` runs the real Rust CLI against the real JavaScript page host (events through a handle and the host ending them with the handle, callbacks called by the page, `types` narrowed by the key, and a host that does not state each feature).
- **Release:** needs a Rust release (the lead tags it); no version is bumped here.

### Fixed: a flaky `wsh mcp` reconnect test (#229; test only)

`test/rust/wsh-mcp.test.mjs` "more than 200 messages held while reconnecting" failed once on CI with `11 !== 10`. The cause was in the test, not the bridge: its `initialize()` helper writes `notifications/initialized` and returns at once, and the test then closed the host. The bridge reads the client's input independently of its connection, so when it read that notification after noticing the loss, the notification was held, took one of the 200 places, and 11 requests (not 10) were refused. The bound counts every message held, requests and notifications alike; that is unchanged. The test now makes one request round trip before closing the host (an answered request proves every line written before it was already read and forwarded), and a second test pins the counting (one held notification, 199 requests held, 11 refused). No wire or product change; nothing changes for a user of `wsh mcp`.

## 0.51.0 / Rust `rust-v0.18.0`

Three JS features of #219 (events through a handle, typed remotes, an MCP face for allow-listed object paths) and the Rust `wsh-objects` client, in one release. The Rust client is the values, events and handles part of the protocol: **callbacks are not built in the Rust client, and events through a handle are a JS feature of this release that the Rust client does not have** (it neither writes the `handle` parameter of `subscribe` nor uses `types`; it ignores the `handle-events` and `types` strings a host states). Nothing else in the Rust crates changed besides the workspace version.

### Events through a handle (#219; JS)

`on(use(handle).path, type, listener)` (and `on(use(handle), type, listener)` when the handle is the source itself) subscribes to an event source reached through a handle of a root that opted in to handles. **Wire: one new optional parameter, `handle`, on the existing `subscribe` request of the `wsh-objects` rpc protocol, and one new string in the `features` list of the `roots` answer (`handle-events`, stated only by a host with a handles root). No new message type, channel or `ServerHello` feature.**

- **The same rule as a path subscription, for the path that produced the handle, extended as written.** The host needs an `allow.on` entry that names that path and the type exactly (no wildcard in either), the key's `objects:ROOT:on` capability, and `authorize` (asked with the extended path and the type). `get` and `call` never imply it, and a handle to an object reached by another path does not inherit the entry. A node handle keeps its `nodes: true` and graph-member rules.
- **It ends with the handle.** `release(handle)` removes the page's listener and drops what it had queued; the session ending, Stop, a navigation and a revoke end it as they end a path subscription. A handle released while its subscription was being authorized leaves no listener. The same bounds (`maxSubscriptions`, the rate, size and queue limits) and the same drop counting apply, shared with path subscriptions. The re-check after `authorize` also closes a race in which two simultaneous subscriptions could pass `maxSubscriptions`.
- **Older peers.** A 0.50.0 client never writes a handle subscription (it refuses with a `TypeError`), so a new host is unaffected by it. A new client against a 0.50.0 host (which does not state `handle-events`) refuses with a named `unsupported` error and sends nothing, rather than sending a request the old host would answer as "no such root". Rust peers do not speak `wsh-objects`.
- The `features` list a host with handles states is now `events`, `callbacks`, `handles`, `handle-events`.

### Typed remotes (#219; JS)

**Wire: one new method, `types`, on the existing `wsh-objects` rpc protocol, and one new string, `types`, in the `features` list of the `roots` answer. No new message type, channel or `ServerHello` feature; nothing in `spec/wsh-v1.yaml`.** A 0.50.0 host does not state `types`: a new client then refuses `rootDescription` with a named `unsupported` error and sends nothing; a 0.50.0 client never calls the method. Rust peers do not speak `wsh-objects`.

- **`describeRootTypes(description, { name })`** (`@johnhenry/wsh/objects-types`, a new browser-safe entry point) is a pure function that returns the text of a `.d.ts` for one root. `rootDescription(page.window)` (`@johnhenry/wsh/objects`) fetches the description: the host's allow-list entries for the root, narrowed by **the connecting key's** `objects:ROOT:OP` capabilities, and the host's type map. Only what the key may do appears (a path no entry names, an operation the key lacks and a refused member are not in the file at all); plain values are `RemoteValue<unknown>`, calls `RemoteCall<unknown[], unknown, ...>`, wildcards `RemoteUntyped`, events typed `on` overloads from `allow.on` and `eventFields`, assignable keys a typed `set`.
- **A host-supplied type map**: `exposeObjects({ types })` and `createPageHost({ expose: { ROOT: { types } } })` (`value`, `args`, `result` and `data` type texts by literal path). It is host-authored text that travels to the far side, so it is checked when the host is created and again by the far side (`checkTypeText`: a conservative subset of type syntax; no new line, comment, `import`, `typeof`, declaration, template literal, unbalanced bracket or `;` / `,` that could end the declaration it sits in; bounded to 1024 characters a text, 256 entries and 32 KiB a root), refused unless an allow-list entry names its path for the operation it types, copied as text and **never evaluated**. A bad text is a `TypeError` where the host is configured.
- **`Remote<T>`, `RemoteRoots<T>`, `RemoteHandle<T>`** (types only) for hand-written value types: `client.openObjects<RemoteRoots<{ shop: Shop }>>()`. `set` and `on` check the key and the event type for a generated (branded) reference and stay permissive for an untyped one; `use(handle)` returns a `Remote<T>` for a typed handle.
- **`wsh-objects-types`**, the package's second bin (JS only; the Rust CLI has no `wsh-objects` client): connects like `wsh-mcp`, prints the declarations of one root, and writes a file only with `--out` (not over an existing file without `--force`).
- A reference is `PromiseLike`, not a `Promise`: the types say so (there is no `catch` or `finally` on a reference).

### An MCP face for allow-listed object paths (#219; JS)

**Wire: nothing new.** The tools are served on the existing `mcp` rpc channel (or `serveMcpOverDuplex`) with its existing methods; no message type, field, channel or feature string was added, so any released MCP-speaking peer (npm 0.49.0 and 0.50.0, the Rust CLI's `wsh --sealed --via ... mcp`) lists and calls them like any other tool. Rust has no `wsh-objects` host.

- **`exposeObjects({ mcp: { tools } })`** (and `createPageHost({ expose: { ROOT: { mcp: { tools } } } })`, paths relative to the root) makes **exactly the paths it names** into MCP tools, each a host-authored `name`, `description` and JSON Schema: a **call** of one method, or a read-only **get** of one value. Nothing is a tool by being allowed; a path the allow-lists do not name for that operation, a wildcard, a path through a call result and a name that needs listing are refused when the host is created. The handler carries `mcpTools` / `mcpToolNames` for `webmcpTools({ tools, allow })`; a page host merges them with the page's WebMCP tools in one handler.
- **A tool is read-only only when the host says `readOnly: true`**, a get included (a getter can have effects, and the mark skips the approval): with nothing said a tool asks the person like any other.
- **The same approval, bounds and label as the WebMCP bridge** (it is the same handler): a tool not marked read-only (a call, by default) asks the person at the page; the input, result, schema, in-flight and per-minute bounds; results are labelled untrusted page content; a page function that throws is an error result without a stack.
- **Arguments are validated before the person is asked and before the page runs anything**, against a small bounded subset of JSON Schema (`src/objects-schema.mjs`: `type`, `enum`, `const`, `properties`, `required`, `additionalProperties`, `items`, `minItems`, `maxItems`, `minLength`, `maxLength`, `minimum`, `maximum`, `anyOf`). A schema with any other keyword (`$ref`, `pattern`, `oneOf`, ...) is refused when the host is created, so what is advertised is what is checked. Arguments and results are plain data only; there is no handle, event or callback through MCP.
- **Two notations, both required.** A key lists and calls a tool only if it holds `mcp:TOOL` (or `mcp:*`) **and** the operation on the root (`objects:ROOT[:call|:get]`); the `objects:` grant is asked again when the tool runs, with the allow-list, `authorize` and the window guard (`createObjectsServer(...).invoke`, new, runs one `get` or `call` through exactly the checks of an objects call). A key with `mcp:TOOL` and no `objects:` entry sees no tool.
- **Internals.** `webmcpTools` honours a host-only part of a tool definition (`INTERNAL_TOOL`: who is calling and the key's grants for `execute`, an argument check before the approval, and a per-key availability hook) only for the definitions the host passes in `tools`, never for a tool the page registers itself (a test forges it from a page tool and it is ignored).

### Rust: a `wsh-objects` client and `wsh objects` (#219; `rust-v0.18.0`)

**Wire: nothing new.** The Rust client now speaks the existing `wsh-objects` rpc protocol (written down in `spec/objects.md`, shipped in the package) to a JS host: a page host behind a relay, or `exposeObjects` on a memory host. A released JS peer (0.50.0 and before) sees an ordinary client; a released Rust peer (`rust-v0.17.1`, `deny_unknown_fields`) has no objects client and is unaffected. The Rust server still serves no `wsh-objects`.

- `wsh_client::objects`: `ObjectsClient::open`, `roots()`, a `Target` (root or handle) with `get`, `call`, `construct`, `set`, `snapshot`, `describe`, `resolve(Chain)` (a whole chain is one request) and `subscribe` (a bounded `Subscription`; drops by the host and by this side are both counted and told); `Handle`s released by `release()`, on drop and at the end of the session; typed `ObjectsError`s (`Refused`, `Limit`, `NotFound`, `Unsupported`, ...) carrying the host's reason; values as a serde-friendly `Value` (bytes native, non-values named). A feature the host did not state (`events`, `handles`) is refused locally by name before anything is sent. Not built: callbacks, events through a handle.
- `wsh --sealed [--via RELAY] objects user@host roots | describe | get | call | construct | set | snapshot | watch | session`: sealed sessions only; JSON on stdout; text from the page is printed as JSON strings with every control character escaped; exit 3 refused, 4 not found, 5 unsupported.
- `wsh-core`: `CborSequenceDecoder::feed_values`, `encode_cbor` and `to_json` expose the rpc codec's CBOR values (a byte string stays a byte string); `WshClient::open_rpc_values` and `RpcChannel::send_values` / `recv_values` use them. `feed`, `open_rpc` and the existing channels behave as before (a byte string is still refused there).
- Tests: unit tests of values, paths, error mapping, events, handles and escaping; `test/rust/wsh-objects.test.mjs` runs the real binary against a page host through a recording relay (allowed and refused paths, the always-refused names, a `get`-only key refused `call`, an event burst with drops, a handle used across calls and released, a host without `events` / `handles`).

## 0.50.0

npm only (since `rust-v0.17.1` the only change under `crates/` is the unit test of the capability vectors added in 0.49.0, no binary changes, no `rust-v` tag; the note below in `spec/wsh-v1.yaml` is a comment that generates no code change). **Wire: nothing new.**

### A rpc handler that authorizes for itself (#220; JS)

`handler.authorizesItself = true` on an rpc handler (an `mcp` handler of an adapter, say) says it asks the host's own `permits` for every call. A host then opens its channel for any key that the key's options and expiry let in, **without demanding `mcp:*` (or `rpc:NAME`, or a named tool) of the key's capability list**; the handler's own checks decide. A handler without the flag is checked as before (`mcp:*`, or a named tool for a `capabilityScoped` one), and `restrict` without `permit-mcp` and an expired key still refuse first. `spec/capabilities.md` lists the request field `authorizesItself`.

### Documentation

`spec/wsh-v1.yaml` records, as a known inconsistency, that `GatewayFail` code `5` is "gateway disabled" on the Rust `wsh-server` and a timeout on the Node gateway and in netway (and names 6 and 7); behaviour is unchanged (tracked in an issue). The bundle budget and the README size table were rewritten by `npm run size -- --update`.

A released JS peer (0.49.0 or 0.48.0) and a released Rust peer are ordinary peers of a session over a duplex; nothing in them changes.

### wsh over a caller-supplied duplex: `@johnhenry/wsh/duplex` (#220; JS)

`serveWshOverDuplex(host, { send })`, `connectWshOverDuplex({ send }, credentials)` and `createDuplexSocket({ send })` run a whole wsh session (login, host-key proof, sealed session, channels) over a duplex of messages another library provides (a mesh channel, a `MessagePort`), so a browser with no relay can be reached by hopping through a mesh peer and a pod can reach a wsh host without a relay. The design, what the duplex must guarantee (reliable, in order, a known maximum message size, backpressure by a returned promise, one connection per duplex) and what a hop can and cannot do is `spec/duplex-binding.md` (shipped in the package).

- **Sealed by default.** The host serves a duplex only sealed, whatever its own `sealSession`; the client seals or fails and binds its login to the host key (`requireChannelBinding: ['host']`); there is no TLS binding on this transport, and the host-key proof plus the sealed session carry the authentication. `allowUnsealed: true` lifts it, said out loud. A client must name the host key it expects (`expectHostKey`, `knownHosts`, or `trustOnFirstUse: true`); a password login is refused unless unsealed is allowed.
- **A connection may now be required to seal:** `host.accept(socket, { sealSession: 'require' })` / `bindSocket` (internally `attach({ sealSession: 'require' })`). It can only strengthen the host's setting; a host with no host key, or one that gave the connection data streams, refuses to attach it (fail closed) instead of serving it unsealed.
- Bounded: messages are cut to `maxMessageBytes` (default 64 KiB) and a larger incoming one ends the link; what waits for `send`, or for a listener, is bounded by `maxBufferedBytes` (4 MiB); a `send` that throws ends the link.
- Tested over an in-memory duplex with a hostile middle that reads, changes, drops and repeats messages: it reads nothing after login, an altered message delivers nothing altered and runs nothing, a repeated one does not run twice, a middle that answers as the host is refused by a client that named the key, and a plain client over the duplex is served nothing.

## 0.49.0

npm only (the Rust crates changed only in a unit test of the capability vectors; no binary changes, no `rust-v` tag). **Wire: nothing new.** No message, field or feature string was added; a 0.48.0 peer and a released Rust peer (`rust-v0.17.1`) interoperate unchanged. Everything below is exports, one specification with its vectors, and seams in the object and MCP layers (#220, the wsh side of making wsh and browsermesh a pair; wsh still has no dependency on browsermesh).

### The notation of key capabilities, written down once, with vectors that ship (#220)

- **`spec/capabilities.md`** is the grammar of a capability (`exec`, `pty`, `relay`, `fs:read|write`, `gateway:...`, `unix:...`, `endpoint:`, `target:`, `rpc:NAME`, `mcp:TOOL`, `objects:ROOT[:OP]`), what each `*` matches and does not (`*.example.com` is not `example.com`; `/srv/*` is not `/srv`), what each request kind needs, the order of the checks (expiry, options, list), and that an entry an implementation does not understand fails closed (the whole list permits nothing; a key line that holds it is refused).
- **`spec/capabilities.vectors.json`** (`version: 1`; 32 list cases and 145 request cases): "does a holder of list L permit request R" for every form and the wildcard edge cases. The JS evaluation and the Rust `wsh-server` both run it. A case names the host classes it applies to; **the Rust server's subset is stated by refusal**: a key line with an `objects:` capability is refused at load (`unknown-capability`), unchanged, rather than accepted and ignored. Running both found no disagreement.
- **Shipped in the package:** `files` now has `spec/*.json`, `spec/*.md` and `spec/wsh-v1.yaml`, and `exports` has `./spec/*.json`, `./spec/*.md`, `./spec/wsh-v1.yaml`: `import vectors from '@johnhenry/wsh/spec/capabilities.vectors.json' with { type: 'json' }`.
- **`@johnhenry/wsh/capabilities`** (new, stable, browser-safe): `permits(capabilities, request, { expires, now })`, `checkCapabilities(...)` (the refusal, `{ code, capability }`), `parseCapabilityList`, `CAPABILITIES_NOTATION_VERSION`. It is the evaluation the hosts already ran, exported; no list, an entry it does not know or a request kind it does not know permits nothing.

### `@johnhenry/wsh/identity`: one module for a key's names, and an `authorized_keys` line builder (#220)

- New stable, browser-safe entry point. `fingerprint(raw)` (hex SHA-256) and `podId(raw)` (base64url of the same bytes), `fingerprintToPodId` / `podIdToFingerprint`, `rawKeyToOpenSsh` / `openSshToRawKey` / `parseOpenSshKey` / `publicKeyToOpenSsh`, `identityOf(key)` (all four spellings), `normalizeIdentity`, `authorizedKeyLine(key, { capabilities, expires, comment })`.
- **`authorizedKeyLine` refuses unsafe input:** `capabilities` is required (a line with none may do everything: say `allowFullAccess: true`), every capability must be one the notation knows, `expires` must be a readable timestamp (written in UTC), the comment may hold no control character or line break, the key must be a plain 32-byte Ed25519 key, and the line it built is read back through the host's own parser and must give the grant that was asked for.
- **Behaviour change (stricter, bug-fix direction):** `fingerprintToPodId` now requires exactly 64 hex digits (it accepted any even-length hex string, so a short or long input gave a name that is not a pod id) and `podIdToFingerprint` exactly 43 base64url characters in the canonical spelling (it accepted any base64url text, and a non-canonical last character that named the same key as another id). Both are still `TypeError`s for anything else. The functions are the same ones the root entry exports; the dev dependency `@johnhenry/browsermesh-primitives` moves from `^0.2.0` to `^0.5.0` (the parity test, still a dev dependency only).

### The `GatewayFail` code table as data (#220)

`GATEWAY_FAIL`, `GATEWAY_FAIL_TABLE` (name, number, meaning), `GATEWAY_FAIL_LOCAL` (the client-made `UNSUPPORTED` 0) and `gatewayFailName(code)` are exported from the package root; the Node gateway and the page host send from the same object. It is a superset of what `@johnhenry/browsermesh-netway` mirrors by hand, name for name and number for number. The table says what the spec's list does not: code `5` is a timeout on the Node gateway and "gateway disabled" on the Rust server (`spec/wsh-v1.yaml` lists `5=GATEWAY_DISABLED` and omits 6 and 7).

### Test doubles in `@johnhenry/wsh/testing` (not stable, like the rest of that entry) (#220)

`createInProcessPipeRelay({ tap, relayOptions })`: the real pipe relay in this process, with a `WebSocket` that dials it (`new env.WebSocket(pipeUrl(base, id, role))`), `env.recorded` (every message it wrote, before `tap`), `env.tap` (return `undefined` to pass, `null` to drop, bytes or an array to write instead), `dropAll()`, `stats()` and `close()`. `createMemoryPair({ host, username, keyPair })`: a memory host and a client already logged in to it, with a key it made and authorized. The entry's whole-bundle size grows from 2.6 kB to 75.7 kB gzip because it now carries the memory host and the relay; `import { encodeRecord } from '@johnhenry/wsh/testing'` is 0.9 kB (the doubles are separate exports a bundler drops).

### What a mesh adapter needs from the object and MCP layers (#220)

- **A transport-neutral caller identity.** `authorize(who, op)`, a prompt and `onCall` see `{ username, fingerprint, podId? }`: `fingerprint` is the hex hash of the caller's key wherever the caller came from; `podId` is there when the transport knows the caller by one (then `fingerprint` is derived from it). `createDuplexPeer({ send, who })` and `server.attach(peer, { who })` take an identity object, and so does `ctx.who` of a handler (`exposeObjects`, `webmcpTools`) called by an adapter; an identity that names two keys, or is not an identity, is refused when it is given. **A wsh caller keeps exactly the `{ username, fingerprint }` it had.**
- **`createDuplexPeer({ permit })`:** the transport's own capability check, asked for each operation (`get`, `call`, `set`, `on`, and `walk`); `on` is `on`, not `get`. A `permit` that throws or answers anything but `true` refuses (before, a throw escaped as a failure of the call). A key's listed roots, previews and `describe` honour it the same way.
- **`serveMcpOverDuplex(handler, { send, who, permits, maxMessageBytes, maxInflight })`** (from `@johnhenry/wsh/page`): the handler of `webmcpTools` (or any rpc handler of the `mcp` protocol) served over a bare `send` / `receive` pair. **The far side speaks plain MCP**: JSON-RPC 2.0 messages as objects; an MCP SDK `Client` connects through any `Transport` that moves them (the tests do exactly that, over an in-memory call). The handler's bounds, approval hook and untrusted labelling are unchanged; the seam adds a message size bound in both directions (1 MiB), requests in flight (64), one answer per id, and refuses anything that is not JSON-RPC 2.0 (no batches). It authenticates and seals nothing: that is the transport's to establish.

### Asked for by the browsermesh adapter (#220)

- **List and call are told apart.** The `permits` hook of `webmcpTools` / `serveMcpOverDuplex` is asked `{ kind: 'mcp-tool', op: 'list', tool }` to list and `{ kind: 'mcp-call', op: 'call', tool }` to call (it was `mcp-tool` for both), so an adapter can scope them separately. The notation's `mcp:TOOL` still covers both.
- **`createPageIndicator(window, { name })`** (from `@johnhenry/wsh/page`): the page host's badge as its own function (`show(who, stop)`, `hide`, `ensure`, `destroy`), with the best-effort caveat.
- **A sealed-session host says so.** With `sealSession: 'require'` a login is not yet a session that can do anything (a client that never seals is served nothing): `auth.authorize(who)` gets `who.sealRequired: true`, and `createMemoryHost({ onSealed(who) })` is called once when a session has been sealed, which is where an audit or an indicator belongs. Nothing changes for a host that does not require sealing, and the login itself is not refused (a login refusal would need a client-stated feature, which is wire).
- **`{ username: null, fingerprint: null, podId }`** is accepted as an identity as it is (the fingerprint is derived).
- The README says how the CLIs dial a pipe relay (`wsh-mcp --sealed ... wss://relay/r/<id>`, `wsh --sealed --via wss://relay/r/<id> mcp user@host`). Left as it is: the channel-open check that a `capabilityScoped` handler on a wsh host needs `mcp:*` when the host has its own `permits` belongs to the wsh host path; `serveMcpOverDuplex` has no such check and opens for whatever its adapter decides.

### Documentation

The README's "Family" section is now "wsh and browsermesh": the pair (wsh is the authenticated, capability-scoped door into one machine or page; browsermesh is the peer fabric), where they meet (the mesh's wsh peer link, the relay's pipe route, netway's gateway backend, objects and MCP over a mesh channel), what is deliberately not shared (sealing schemes, wire codecs, addressing, exec; machine rights are never granted from mesh trust), that wsh has no dependency on browsermesh, and when not to use one key in both worlds. A subsection of the capabilities section explains the notation exports, and the Security model says what objects and MCP over a transport that is not wsh do not protect.

**A released peer:** nothing here is on the wire, so a 0.48.0 or earlier JS peer and a released Rust peer are unaffected. An adapter that uses `createDuplexPeer({ who, permit })`, an identity object in `attach`, or `serveMcpOverDuplex` needs 0.49.0 of this package: an older `createDuplexPeer` ignores `who` and `permit` (it would serve with no identity and no capability check), so an adapter must require `>=0.49.0` rather than rely on them being honoured.

## 0.48.0

npm only (no Rust crate changed since `rust-v0.17.1`). **Compatibility:** handles and callbacks need a 0.48.0 host AND client. A 0.47.0 client does not recognise a handle (it sees an unnamed value); a 0.47.0 host does not accept callbacks (it ignores the field and would run the call with `null` in place of the function),
and a 0.48.0 client therefore refuses to send a function to a host that has not said it supports callbacks (a named error, `reason: 'unsupported'`; the host states `features` with its roots, additive and ignored by older clients). A pre-0.48 client against a 0.48.0 host that has opted in to handles gets an unnamed value for a handle.
The wide-open handles string from early drafts was never released and is refused with a sentence. The two opt-ins of handles are per root: `nodes` (DOM nodes, windows, documents) and `wideEntries` (a wildcard in `call` or `set`).

### `wsh-objects` callbacks: a far-side function as an argument of a call that accepts one (#190; JS)

`allow.call: ['window.app.subscribe(callback)']`: an entry that ends in `(callback)` says the call accepts functions as arguments. The page's function receives a **stub** it may keep and call with plain values; the far side's function runs on the far side.
A call entry without the suffix refuses a function argument (`does not accept callbacks`); a function nested in an argument, a remote reference and a handle are still refused where they are written.

- **One-way:** the stub returns `undefined` at once, so the page cannot be made to wait for the far side; the far side's return value is not delivered (no notation for it yet). Its arguments are plain values only (what cannot be cloned is `null`; never a handle).
- **Bounds:** `maxCallbacks` (16 per channel, refused by name), `maxCallbacksPerSecond` (20 per callback), `maxCallbackBytes` (16384); calls over the rate, the size or the shared queue are dropped and counted, and `onCallbackDropped({ dropped })` tells the client before the next one. They go through the channel's credit.
- **Dead after the session:** the channel ending (leaving, Stop, a navigation, a revoke) and `release(fn)` kill the stub; calling it is a counted no-op. A far-side listener's error goes to `onCallbackError` and never reaches the page. The call is a `call` for `authorize` (`op.callbacks`) and for `objects:ROOT:call`.
- **Wire: nothing new beyond the channel:** a `callbacks: [[argument index, id]]` field on a call or construct op, the method `releaseCallback`, and the notification `callback`. **A released peer (0.47.0):** an older host ignores the unknown `callbacks` field and would run the call with `null` in place of the function, so this client refuses to send a function unless the host's `roots` answer lists the `callbacks` feature (a named error); an older client cannot pass one.

### `wsh-objects` handles, on the path-bound model (#190; JS)

A root can opt in to **handles** (`exposeObjects({ handles: { window: {} } })`, `createPageHost({ expose: { window: { mode: 'handles' } } })`): a function or an object that is not plain data comes back as an opaque `RemoteHandle`
instead of a named non-value, and `use(handle)` makes a reference that stands on it; `release(handle)` gives its place back. Values stays the default, and the opt-in is per root. The wide-open string from the first design is not accepted: the allow-lists apply to handles too.

- **Path-bound:** a handle stands at the path that produced it (`a.b` for a get, `a.f()` for a call, its members `a.f().x`), and every operation through it is judged by the allow-lists for that path extended by the member. A handle never widens what a path grants; the always-refused names and the entries that must name their path stay refused through it.
- **Opaque and local:** a 128-bit random id (from the CSPRNG: the page host uses its window's), meaningful only on the channel that produced it and for the key that holds it; nothing of it is enumerable on the far side, it is not thenable and not an argument.
- **Nodes and the window graph** (Node, Window, Document) are not handed out as handles unless the root sets its own `nodes: true`; even then `ownerDocument`, `defaultView`, `parentNode`, `parentElement`, `getRootNode`, `contentWindow`, `contentDocument`, `self`, `window`, `top`, `parent`, `frames`, `opener`, `globalThis` stay refused until an entry names them.
- **Bounded:** `maxHandles` (64) per channel, refused by name on overflow and never evicting; everything is released when the channel ends (leaving, Stop, a navigation, a revoke). A preview (up to 8 member names) is present only where a `get` entry names the path.
- **Previews list only walkable names** (those `describe` would list), and **a wildcard in `call` or `set` on a handles root needs `wideEntries: true`** (or the paths listed): without it the host refuses to start with a sentence saying so. `get`-only wildcards and values roots are not affected.
- **Capabilities unchanged:** `objects:ROOT[:OP]` apply, and an operation through a handle is the same get, call or set of the producing path.
- **The indicator is described as best effort** in the README: page code can remove a DOM element; Stop, revoke and the key's capabilities are the controls that hold.
- **Not built:** callbacks as arguments, events through a handle.
- **Wire: nothing new beyond the `wsh-objects` channel:** a result `{ h, kind, type?, preview? }`, requests that start from `{ handle }` instead of `{ root }`, and the method `release`. **A released peer (0.47.0):** a 0.47.0 host never returns a handle; a 0.47.0 client against a host that does would not recognise `h` (it sees an unnamed value), so use this release on the client when a host opts in.

## 0.47.0

npm only (no Rust crate changed since `rust-v0.17.1`). New API: `@johnhenry/wsh/objects` events, and `objects:ROOT[:OP]` key capabilities. **A key line with an `objects:` capability is refused by older JS hosts (0.46.x and before) and by `wsh-server`** (unknown capability: the key does not log in): use this release on the host before adding one.

### `wsh-objects` events in values mode: `on(ref, type, listener)` (#190; JS)

A far side can listen to events of a source the host names: `allow.on: ['window.app.bus@ready', 'window@hashchange']` (`path@type`; the source and the type are named exactly: a wildcard in either is refused when the host is created), and `await on(ref, 'ready', (data, { type, seq, dropped }) => ...)`, which resolves to the
function that unsubscribes (`off(fn)` does the same). `createPageHost({ expose: { window: { allow: { on: ['@hashchange'] }, eventFields } } })` offers it on a page host (`'@type'` is the root itself).

- **Plain values only, never the event, a node or a handle.** An Event arrives as `{ type, timeStamp, isTrusted }` plus the fields the **host** lists for that type in `eventFields` and the subscriber asked for (each copied as plain data; a node
  is left out; an unlisted field is refused). An emitter's arguments arrive as `{ type, args }`.
- **An entry of its own:** an event source is never implied by `get` or `call` or by a wildcard in another list. The always-refused names, the entries that must name a path, `authorize(who, op)` (`op.type`) and the key capability
  `objects:ROOT:on` all apply.
- **Bounds, refused by name or counted:** `maxSubscriptions` (16 per channel, refused), `maxEventsPerSecond` (20 per subscription), `maxEventBytes` (16384) and `maxQueuedEvents` (100 per channel): an event over any of those three is dropped, and the
  next one delivered carries `dropped`, how many were lost before it. Events are notifications written through the channel's credit, so a slow reader fills the bounded queue and loses events, counted.
- **A dropped event costs a counter:** the per-subscription rate and the queue room are checked before the event's fields are read or copied.
- **Cleanup:** every listener is removed from the page's sources when the channel ends: the operator leaving, Stop, a navigation, a revoke. A listener error on the far side goes to its `onError` and never reaches the page; the host's listener only copies and queues.
- **Not built:** callbacks as arguments of a call (the design describes them as handles; a function is refused where it is written), handles.
- **Wire: nothing new.** Two rpc methods (`subscribe`, `unsubscribe`) and a notification (`event`) on the existing `wsh-objects` channel. **A released peer (0.46.x):** a released client has no `on`; a released host answers `method not found` to `subscribe`
  (so `on` fails against it with a clear error); a released host's key lines refuse `objects:ROOT:on` (unknown capability: fails closed).

### `objects:ROOT[:OP]` key capabilities for `wsh-objects` (#190; JS)

A key's capability list can now limit it to named roots and operations of a `wsh-objects` host: `objects:window` (every operation on that root), `objects:window:get` (`get`, `call` or `set` only), `objects:*:get` (every root).
`exposeObjects` enforces it through the handler context's `permits` (asked afresh for each operation, so `expires` holds at call time), **intersected with the host's allow-lists: a capability never widens them**.

- **No default changed.** A key with no capability list is unlimited as before, and one with only `rpc:wsh-objects` keeps today's behaviour (every root, every operation the lists allow). A key that names roots is limited to them, is not told of the other roots, and
  may open the channel without `rpc:wsh-objects` (the `wsh-objects` handler declares `capabilityScoped`, as `mcp` does for `mcp:TOOL`).
- **A released peer.** No wire change. A released JS host (0.46.x) does not know the grammar and refuses a key line with an `objects:` capability (unknown capability: the key does not log in), and so does `wsh-server`: it fails closed. Use this release on the host.
- **Rust:** the Rust CLI's `wsh --sealed --via <relay> mcp` already reaches a page host's `mcp` channel; a test now says so (`test/rust/wsh-mcp-page-host.test.mjs`). No Rust change was needed. There is still no Rust `wsh-objects` client and no Rust host.

## 0.46.1 / Rust `rust-v0.17.1`

### Fixes only: no new option, feature string or wire message, and no default changed. A released peer needs nothing.

### Fix: the Rust client over WebTransport lost control frames that arrived together (Rust)

`wsh` and `wsh-client` read the control stream of a WebTransport connection and handed on only the first frame of each read, dropping the rest of the frames that read had completed (for example the `ServerHello` and the `Challenge` behind it, or a reply and
the message after it). Every frame a read completes is now kept and delivered in order, including after the stream has ended. A `wss://` connection read frames correctly and is unchanged.

### Fix: what a peer sent before its connection closed is delivered before the close, on every JS transport and host (JS)

The same ordering as the entry below, in the places that had it too:
- **`WebTransportTransport`:** the end of the session was reported while control messages already read were still waiting to be dispatched; it now waits for them.
- **A stream that had received bytes when the WebSocket closed** lost them: the stream was failed at once, which discards what is queued. The failure now reaches the reader after the bytes that had arrived (`WebSocketTransport` streams).
- **`bindSocket`** (what `server.accept(socket)` and `host.accept(socket)` run): the socket's close marked the connection closed before the messages already received had been handled, so a peer's last messages (a final write, the end of its input) were dropped. The close now joins the chain behind them.

### Tests: three timing-sensitive tests wait on the event instead of the clock

`pipe-relay` "pairs a host and an operator…" (its relay gave up on a waiting half after 400 ms, which a slow machine exceeded; it has its own relay now and waits on the messages and a ping's pong), `server-sessions` "a ring overflow is reported as a gap by Resume"
(it assumed the process had written everything 600 ms after the drop; it waits for the bytes) and `gateway-udp` "counts against maxConnections…" (the short idle limit could free the slot before the second open arrived; the cap and the idle limit are checked separately). Tests only.

### Fix: the last messages of a connection are delivered before its close is reported (JS client and `WebSocketTransport`)

When the socket closed right behind the last messages of a connection, the close could be handled before those messages had been dispatched: a transport dispatches inbound control messages one per turn, a sealed frame is opened asynchronously, and the socket's
close is a separate event, so the close overtook what was still waiting. What the host said last (the reason it was ending the session, the exit of a command) could be lost, and a caller waiting for it waited forever. `WebSocketTransport` now reports the close
after the messages that arrived before it (`SerialQueue` gained `busy` and `idle()`), and `WshClient` handles the close after the sealed frames that had already arrived have been opened and delivered. No wire change; nothing else about closing is different.

### CI: a hung test now costs minutes and names itself

`npm test` runs `scripts/run-tests.mjs`: the same `node --test` per file as before, with each file announced when it starts and ends, a per-test timeout (2 minutes) that fails the test by name, and a per-file limit (5 minutes) that kills the file and fails the run naming it.
The CI and publish gates also run it under `timeout 1200`; the CodeQL and dependency-review jobs got `timeout-minutes`. (`npm test -- test/x.test.mjs` runs one file.)

## 0.46.0 / Rust `rust-v0.17.0`

### Breaking defaults (read these before upgrading; the entries below say who is affected and what to do)

- **The Rust client verifies the server's certificate on WebTransport connections.** A server with a self-signed certificate (for example `wsh-server --generate-cert`) is refused until the client pins it with `--cert-hash <sha256>`
  (or `ConnectConfig.cert_hash`); `--insecure-skip-cert-verification` is the development-only opt-out. `wss://` is unchanged.
- **`wsh-server` gateway host-name rules reach public addresses only.** A name in `allowed_destinations` no longer reaches a loopback, private or link-local address it resolves to; name the address or range (`"10.1.2.3/32:5432"`) to allow that.
- **`WSH_INSECURE_LOOPBACK_TLS` applies to loopback destinations only** (Rust client and CLI); for any other host the certificate is verified and the client says once on stderr that the variable was ignored.
- **A plain message dropped on a sealed session is counted, not logged:** the JS client no longer writes it to the console; read `client.onDrop` / `client.droppedMessages`.

Everything else in this release is additive (new options, entry points and negotiated features with the defaults unchanged), or a fix.

### `@johnhenry/wsh/objects`: remote objects by path, `values` mode, and `createPageHost({ expose })` (#190; JS)

A host can now name objects as **roots** (a page's `window`, a worker's `self`, any object) and let a key read, call and set the paths an allow-list names. New entry point `@johnhenry/wsh/objects` and the rpc
protocol `wsh-objects`: `exposeObjects({ roots, mode: 'values', allow: { get, call, set }, authorize(who, op), limits })` is the handler for any host's `rpc`; `client.openObjects()` (added by importing the
entry point) returns the roots as lazy references; the helper functions `get`, `set`, `call`, `construct`, `snapshot`, `describe`, `closeObjects` are functions, not methods, so they never collide with a remote property.
`createPageHost({ expose: { window: { mode: 'values', allow } } })` serves it on a page host, beside or without `mcp`.

- **Pipelining:** a reference is a lazy path; `await` sends the whole chain (gets, calls, constructs) in ONE `resolve` request. There is no `eval`, so it works under a strict Content-Security-Policy. Assignment with `=` throws a
  sentence naming `set()`; `ref.then` is the awaiting function and a remote property named `then` is reached with `get(ref, 'then')`.
- **Only cloneable values cross, which is what makes an allow-list of paths mean what it says:** plain data and bytes come back as themselves; a function, symbol, `Date`, DOM node or other object comes back as a named
  `NonValue`, never a handle. What is sent is plain data, copied, and refused if an object has a prototype of its own or a refused key.
- **Always refused:** the segments `__proto__`, `prototype`, `constructor`, `__defineGetter__` and its three siblings, `eval`, `Function`, `import`, `execScript`; `call` / `apply` / `bind` of a function; timers given a string.
  **Refused until an entry names them:** `document.cookie`, `localStorage`, `sessionStorage`, `indexedDB`, `navigator.credentials`, `fetch`, `XMLHttpRequest`, `postMessage`, `open` (a wildcard does not). Per-operation allow-lists by
  path glob; nothing is allowed by default. Getters with side effects are still gets, and the README says so.
- **Bounds, each refused by name:** `maxOps`, `maxArgs`, `maxDepth`, `maxValueBytes` (also kept under the transport's message size), `maxKeys`, `maxRequestsPerSecond`, `callTimeoutMs`.
- **The core is transport-neutral** (`objects-core.mjs`; a duplex seam of `onRequest`, `request` with cancel, `notify`, `onClose`, a per-call identity and a maximum message size; `createDuplexPeer({ send })` is one over a bare
  `send` / `receive`): one test suite runs over a bare in-memory duplex and over a wsh rpc channel.
- **Not built (`mode: 'handles'` is refused with a sentence):** handles, events and callbacks, `objects:ROOT` capabilities, typed remotes. The key capability `rpc:wsh-objects` gates the channel today.
- **A released peer.** No wire change: an rpc channel named `wsh-objects` on the existing `rpc` / `rpc-virtual` feature, advertised like any `rpc-protocol:<name>`. A released JS client (0.45.0) or Rust client (`rust-v0.16.0`)
  can open it where the host serves stream-mode rpc, but has nothing that speaks it; a released host does not offer it. `wsh-server` does not serve `wsh-objects`.
- **Bundle:** `@johnhenry/wsh/objects` is 48.4 kB gzipped; `@johnhenry/wsh/page` grows from 80.8 to 87.6 kB with it. No other entry point changed.

### `@johnhenry/wsh/page`: a page's WebMCP tools served as MCP behind a pipe relay (#190; JS)

A web page can now be a wsh host for **the tools it has registered with WebMCP**, and an MCP client (`wsh-mcp --sealed`, or `client.openRpc('mcp')` with `mcpClientTransport`) can list
and call them. New entry point `@johnhenry/wsh/page`: `createPageHost({ window, relay, name, authorizedKeys, mcp: { allow, approve, tools? }, indicator?, unattended?, hostKey?,
hostKeyStore?, onSession, onRefused })`, `webmcpTools({ window, allow, approve, tools? })` (an rpc handler for `mcp`, usable in any host) and `captureWebMcp(window)`.

- **Key login only, a sealed session required, nothing else offered:** no anonymous mode, no password login, no exec, no file access, no object access (that is a later step of #190).
  The window is passed in and is the only realm touched (a test greps the entry point for ambient globals); passing it exposes nothing by itself.
- **Three sources of tools:** an explicit list (the same definitions given to `registerTool`); a capture shim installed before the application's code, wrapping `registerTool` on
  `document.modelContext` and the older `navigator.modelContext`, honouring abort signals and `unregister()`, and providing a minimal `modelContext` where the browser has none; and
  the browser's own `getTools()` / `executeTool()` where it has them (the current draft's; feature-detected, tested against a fake only).
- **Mapping to MCP:** `tools/list` (name, title, description, schemas, annotations; what MCP lacks in `_meta`), `tools/call` to `execute(input, { signal })` with MCP cancel aborting the signal, structured
  results plus a text rendering, a thrown error as `isError` with the message and never a stack, `notifications/tools/list_changed`. Results are labelled untrusted.
- **Bounds, refused by name:** `maxTools`, `maxSchemaBytes`, `maxInputBytes`, `maxResultBytes`, `maxInflight`, `maxCallsPerMinute` (and `callTimeoutMs`).
- **Safety the browser would have supplied:** an allow-list by tool name (nothing allowed by default); `approve: 'never' | 'consequential' | 'always'` (default `'consequential'`: anything not marked
  `readOnlyHint`) asking the person at the page through `prompt(call, who)`, with an accessible default dialog; a visible indicator with the key's fingerprint and a Stop control (`revoke`);
  `indicator: false` only with `unattended: true`; the host closes, telling the operator why, when the window leaves its origin or closes; a host key per page load, or one kept through an injected `hostKeyStore`.
- **Per-key narrowing, and an additive change to every JS host's rpc context:** `capabilities="mcp:TOOL"` limits a key to those tools. To allow it, an rpc handler's `ctx` now has `capabilities`
  (the key's list or `null`) and `permits(request)`; a handler that filters by `permits` sets `capabilityScoped = true`, and only then may a key holding `mcp:TOOL` but not `mcp:*` open the
  `mcp` channel. **No default changed:** every other `mcp` handler still needs `mcp:*`.
- **A released peer.** No wire change at all: no message, field or feature string is new. The far side is the `mcp` rpc channel in virtual mode that #191 added, so a released JS client (0.45.0)
  and Rust client (`rust-v0.16.0`) refuse it exactly as they refuse any virtual-mode rpc host (they look for `rpc`); use this release's client or `wsh-mcp --sealed`. `wsh-server` is unchanged.
- **Bundle:** `@johnhenry/wsh/page` is 80.8 kB gzipped (it contains the memory host); the other entry points grew by about 100 bytes gzip each at most, from the two small additions to the shared rpc context.

### Behaviour change: `WSH_INSECURE_LOOPBACK_TLS` now applies to loopback destinations only (Rust client and CLI)

The variable (`1` or `true`) skips `wss://` certificate verification, and until now it did so for any host while it was set, whatever its name suggested. It now applies
**to loopback destinations only**: verification is skipped when the socket actually connected to an address in 127.0.0.0/8 or `::1` (decided on the peer address, so `localhost`
counts when it resolves to a loopback address and a name that resolves elsewhere does not). For any other destination the variable has no effect, the certificate is
verified as usual, and the client says once on stderr that the variable was ignored for that host. Loopback test setups keep working unchanged; anyone who set it to reach a
remote server with a self-signed certificate must trust that certificate instead (`SSL_CERT_FILE`). The JS client never read the variable.

### rpc channels in virtual data mode, Rust: `wsh mcp --sealed` / `--via` and `wsh-server` with `seal_session` on (#191; Rust)

The Rust halves of the JS change below. **No new wire format**: the feature string `rpc-virtual`, `OpenOk { data_mode: "virtual" }`, `SessionData` and the flagged
`GatewayCredit` (`gateway_id = 0x80000000 | channel_id`, 262144 bytes per direction) are exactly what the JS side states.

- **Client.** `wsh-client`'s `RpcOffer` reads `rpc-virtual`; `WshClient::open_rpc` chooses the form from what the host states (nothing for callers to change) and the channel
  keeps credit as the JS `RpcCreditLink` does: a slow reader bounds the sender, an overrun closes the channel, the message cap is enforced from the CBOR header. The
  refusals of `wsh mcp --sealed` and of rpc on a sealed session are gone: `wsh mcp --sealed` and `wsh --via <pipe relay> mcp` work against a JS host (a page host, a
  reverse host). The shared accounting is `wsh_core::rpc_credit`.
- **Server.** With `[server] seal_session = "offer" | "require"` the typed rpc channels (`wsh-host`, and `wsh-fs` when `[rpc] fs_root` is set) are offered, stated
  `rpc-virtual` instead of `rpc`, riding `SessionData` (inside the seal on a sealed session) with the same credit accounting, and with the per-key capability checks of
  stream-mode rpc applied identically (`rpc:NAME`, `fs:read` / `fs:write`, file transfer: one code path). The start-up message that withheld rpc is gone. **With
  `seal_session` off (the default) rpc is stream-mode and unchanged.** Under `offer`, a client that does not seal also gets `rpc-virtual` (plain `SessionData`).
- **A released peer.** A released JS (0.45.0) or Rust (`rust-v0.16.0`) client looks for `rpc`, which a sealing server does not state: it refuses with
  `UNSUPPORTED_PROTOCOL` before sending anything (before this change such a server offered no rpc at all, so nothing that worked stops working). A released host never
  states `rpc-virtual`, so the new client uses streams there. Not covered: WebTransport (never sealed on `wsh-server`; it offers no rpc, as before).

### Host option `usernamePattern` (additive)

`createWshServer`, `createMemoryHost` and `createConnectionFactory` take `usernamePattern` (a `RegExp` or a pattern string): which login names the host admits. **Default unchanged**,
`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`. A host that does not map names to OS accounts (a page host, a mesh peer named by a base64url identity hash that may start with a digit or `-`) can
admit its own shape, for example `/^[A-Za-z0-9_-]{1,64}$/`, and no longer needs to prefix the name. Whatever the pattern, a name is 1 to 256 characters with no control character, no
`/` or `\`, and is not `.` or `..`, and a pattern that matches the empty name is refused when the host is created.

- **Wire:** none (a name is a string in `Hello.username` as before; the check is the host's). **A released peer:** a released client sends what it always sent; a released host keeps its
  own default and refuses such a name with `bad username`, so a client that relies on this option needs a host from this release. The Rust `wsh-server` and `createReverseHost` keep the default shape.
- Tests: `test/username-pattern.test.mjs` (default unchanged and refusing digit-first and dash-first names, a pattern on a Node host and a memory host, the floor under a pattern that
  matches anything, option validation). The floor was broken once to see its test fail.

### Typed errors for a refused login and a failed connection (additive; JS client)

`connect()` now rejects a refused login with `WshAuthError` and a failed connection with `WshConnectionError`, the way a host-key mismatch is a `HostKeyError`. **Both are `Error`s and the
messages are unchanged** (`Authentication failed: key not authorized`, `Connection failed across transports (...)`, `Auth handshake timed out ...`), so code that matches the text keeps working.

- `WshAuthError`: `code` (`AUTH_UNAUTHORIZED`, `AUTH_BAD_SIGNATURE`, `AUTH_METHOD_DISABLED`, `AUTH_RATE_LIMITED`, `AUTH_KEY_EXPIRED`, `AUTH_BINDING_REQUIRED`, `AUTH_NOT_SEALED`, `AUTH_BAD_REQUEST`, or `AUTH_FAILED`),
  `reason` (the host's words, verbatim) and `refusal` (the reason the host reports to its own `onRefused`, or `null`). `WshConnectionError`: `code` `CONNECTION_FAILED` (with `attempts`) or `HANDSHAKE_TIMEOUT`.
  Also exported: `WSH_ERROR_CODES`, `classifyAuthRefusal(reason)`.
- **Wire: none.** The `AuthFail` message carries only the host's text, so the client recognises the reasons of the Node host and the Rust `wsh-server` from their wording; a test runs each refusal
  against a host and checks the client's `refusal` equals what the host reported to `onRefused`. A host that words a refusal differently gives `AUTH_FAILED`, `refusal: null`, and the text in `reason`.
  Carrying the code on the wire would be a new optional field behind a feature string (a released Rust peer rejects unknown fields); it is not done here.
- **A released peer:** a released host is unchanged and is what the client reads; a released client is unaffected by a newer host.
- Tests: `test/client-errors.test.mjs` (each refusal against a memory host with `onRefused`, rate limiting, a real WebSocket, the classification table, an unanswered handshake, no listener).
  One pattern was removed once to see the tests fail.

### A message a sealed session drops is counted and reported, not written to the console (JS client)

A plain message heard on a sealed session (or before it is sealed), a plain message on a sealed reverse bridge and a bridge frame that does not open used to be dropped with a `console.warn`
(`[wsh:client] dropping a plaintext message ...`) and no signal to the application. Now **nothing is written to the console**: the client counts them (`client.droppedMessages`, `{ plaintext, unopened }`) and calls
`client.onDrop({ reason, messageType?, detail? })` (`reason` is `plaintext-on-sealed-session`, `plaintext-before-seal`, `plaintext-on-sealed-bridge` or `unopenable-bridge-frame`). It is not `onError`: the connection carries on,
and a frame that does not open on a sealed *session* still ends it through `onError` as before. A handler that throws is ignored.

- **Behaviour change:** the console lines are gone. An embedder that read them should read `onDrop` / `droppedMessages`.
- **Wire: none. A released peer:** unaffected (client-side only).
- Tests: `test/session-seal-client.test.mjs` (plain messages injected by a relay after the key exchange are counted, reported with their message type, never reach the console, and a throwing handler changes nothing).
  Not covered by a test: the three sealed-bridge paths (they call the same function).

### Pipe relay: a browser-safe entry, and a "paired" signal for the waiting host (additive; JS)

- **`@johnhenry/wsh/pipe-relay` bundles for a browser.** Its `listen()` (an HTTP server through `ws` and `node:http`) moved to `src/pipe-relay-node.mjs`, which `listen()` loads by name when it is called, so a
  bundler that follows a static import of the pipe relay no longer needs `ws` or `node:http`/`node:https` (the failure a page that imports `pipeUrl` next to `./memory` hit). **The export is unchanged:** `createPipeRelay().listen()`
  works as before. `./pipe-relay` is now a bundled browser entry point (`npm run size` lists it, 3.0 kB gzip), and a test bundles it for the browser next to `./memory`.
- **A host can be told its partner arrived.** `pipeUrl(relay, id, 'host', { notifyPaired: true })` (`?role=host&paired=1`), or `relay.accept(socket, { id, role: 'host', notifyPaired: true })`: the relay sends that host one
  text frame, `wsh-pipe/1 paired` (`PAIRED_FRAME`), when the operator arrives, before anything the operator said. `watchPairing(socket)` returns `{ socket, paired }`: pass `socket` to `accept()` (the frame is kept out of what
  the wsh host reads) and await `paired` (rejects if the socket closes first).
- **Wire / negotiation:** the host opts in with a URL parameter; nothing else changes on the pipe, which is binary both ways. **A released peer:** a released relay ignores `paired=1` and never sends the frame (the host's
  `paired` then never settles and the connection works as before); a released host never asks, so it is sent nothing; an operator is never sent it, whatever it passes. The Rust `wsh` operator side is unaffected.
- Tests: `test/pipe-relay-paired.test.mjs` (the frame, its order against early bytes, a host that did not ask, the operator asking, `accept()` directly, `watchPairing` over a real socket, a login through it), the module-graph
  and bundle tests in `test/pipe-relay.test.mjs` and `test/browser-bundle.test.mjs`. Putting the literal `import('./pipe-relay-node.mjs')` back made the bundle tests fail.

### `@johnhenry/wsh/testing`: the QMux codec primitives, for tests (additive; JS)

A new entry point exports the QMux record and frame codec a test needs to read, change and re-wrap what travels on a connection: `encodeStream`, `encodeRecord`, `RecordDecoder`, `decodeFrames`, `encodeVarint` / `decodeVarint`, the other frame
encoders, `FRAME_TYPE`, `QMUX_ERROR_CODE`, `QMuxProtocolError`. **It is marked as not part of the stable API** (the module header, `@experimental` in the types, `QMUX_TESTING_API.stable === false`, the README): it may change or
disappear in any release and is outside the compatibility policy. The stable entry point (`@johnhenry/wsh`) is unchanged and still does not export them. It is pure JavaScript and is bundled for the browser like the other entries (`npm run size` lists it).

- **Wire: none. A released peer:** not applicable; it re-exports functions the package already contains.
- Tests: `test/testing-entry.test.mjs` (the exports, that the main entry does not have them, the not-stable markers, a record split across feeds, a frame re-wrapped around altered bytes and an unaltered one re-encoding to the same bytes).

### rpc channels in virtual data mode: a sealed session and a host behind a relay can carry rpc (#191; JS)

An `rpc` channel (`Open { kind: 'rpc', command: <protocol> }`, a CBOR sequence of JSON-RPC messages) can now ride the control plane -- as `SessionData`, and inside
`EncryptedFrame` on a sealed session -- where there are no client-opened data streams. So a sealed session carries rpc (`wsh-mcp --sealed`), and a host behind a relay
(`createReverseHost({ rpc })`, a page host over a pipe relay, a memory host with `dataStreams: false`) can offer `mcp`, `wsh-fs`-style and custom protocols.

- **Wire.** One new feature string, `rpc-virtual`, stated by a host **instead of** `rpc` on a connection without client-opened streams (in `ServerHello.features`, or
  `ReverseAccept.features` behind a relay), with the unchanged `rpc-protocol:<name>` and `rpc-max-message:<n>`. `OpenOk` answers `data_mode: "virtual"`. Flow control is
  per direction, 262144 bytes of credit to start, returned in bytes as the receiver takes data in; the credit message is the existing `GatewayCredit` with `gateway_id`
  = `0x80000000 | channel_id` (a number space no gateway id has), so no new message type exists for a relay to drop. A peer that overruns its credit has the channel
  closed; a message over `rpc-max-message` is refused from its CBOR header, before it is assembled. No default changed: a host serves rpc in virtual mode only when it was
  given `rpc`.
- **API.** `createReverseHost({ rpc, rpcMaxMessageBytes, rpcMaxInflight })` (browser-safe and `@johnhenry/wsh/server`'s, which also takes the `wsh-host` / `wsh-fs`
  built-ins); `client.openRpc()` chooses the form from what the host states; `wsh-mcp --sealed` and `runMcpStdioBridge({ sealSession })`; `RPC_VIRTUAL_FEATURE`,
  `rpcVirtualOffered()`, `RPC_CREDIT_WINDOW`; `RpcChannel` option `onConsumed`.
- **A released peer.** A released JS client (0.45.0) opens rpc only when the host states `rpc`; a virtual-mode host does not, so it refuses with `UNSUPPORTED_PROTOCOL`
  before sending anything. A released host never states `rpc-virtual`, so this client opens stream-mode rpc there, unchanged; a host with data streams states exactly what
  it did before. A released Rust client (`rust-v0.16.0`) likewise looks for `rpc` and refuses. A released relay (JS or Rust) forwards `SessionData` and `GatewayCredit`
  as it always has. The Rust halves follow in the entry above.

### **Breaking** (Rust client): the Rust client now verifies the server's certificate on WebTransport connections

`wsh` and `wsh-client` now validate the certificate of an `https://` (WebTransport) server against the system trust store. **Who is affected:** anyone who uses the Rust client over
WebTransport against a server whose certificate is not signed by an authority the system trusts (for example a `wsh-server --generate-cert` certificate). **What to do:** pin the
certificate with `--cert-hash <sha256>` (below), or point the client at a CA-signed certificate. A `wss://` connection is unchanged: it was already validated.

- **New: `--cert-hash <SHA256>`** (global flag, repeatable) on `wsh`, and `ConnectConfig.cert_hash` / `ConnectConfig.cert_hashes` for the library: the server's certificate must
  have one of these SHA-256 hashes, no certificate authority involved, with the rules of the JS client's `serverCertificateHashes` (ECDSA P-256 key, validity of at most 14 days;
  `--generate-cert` makes such a certificate). The value is 64 hex digits, colons allowed, or the whole `SHA256 Fingerprint=...` line `openssl x509 -fingerprint -sha256` prints.
  `wsh-server` now logs its certificate hash at start-up. With exactly one pin the connection also has the `cert-hash` channel-binding kind (it was available to a library caller
  before, but nothing checked the certificate it named).
- **New: `--insecure-skip-cert-verification`** (`ConnectConfig.insecure_skip_cert_verification`), for development only: the certificate is not checked and a warning is printed
  on every connection. It is refused together with `--cert-hash`, and with a password login (a password login cannot be sealed end to end, so the password would go to whoever
  answers the unverified connection); a login by key is still covered by `known_hosts` / `--host-key`.
- `--cert-hash` or the opt-out with a `wss://` URL is an error, not ignored. A target that is tried over WebTransport and then `wss://` applies them to the WebTransport attempt only.
- **Wire:** none. **A released peer:** nothing is negotiated; a released `wsh-server` and a JS host are unaffected, and a released `wsh` keeps its old behaviour.
- Tests: `crates/wsh-client` runs a real in-process WebTransport server with a fresh self-signed certificate: refused by default, accepted with its hash, refused with a wrong hash,
  accepted (with one warning per connection) under the opt-out, and the configuration rules (`cert_policy`) and the hash parser; the CLI's flag handling in `commands/common.rs`.
  The default was broken once to see its test fail.

### **Breaking** (Rust `wsh-server`): a gateway host-name rule reaches public addresses only, as the Node host's does

In `[gateway] allowed_destinations`, a host-name rule (`"db.internal"`, `"localhost:5432"`) now allows that name only at a **public** address, like `"*"`. Before, a name rule also let
the name reach a loopback, private, link-local, carrier-grade-NAT, unique-local or unspecified address it resolved to. A literal-address rule (`"127.0.0.1:5432"`) now matches when
a client asks for that address, not when a name resolves to it; an address range (`"10.0.0.0/8:5432"`) still matches both. The Node host's gateway already worked this way
(`allowPrivate`, 0.38.0). `ResolveDns` answers are filtered the same way.

- **Who is affected:** a `wsh-server` with `enabled = true` whose `allowed_destinations` lists a host name that is meant to resolve inside the host's network. **What to do:** add the
  address or range the name resolves to (`"10.1.2.3/32:5432"`, `"127.0.0.1:5432"`); the name rule can stay.
- **Wire:** none. **A released peer:** nothing is negotiated; a client sees `POLICY_DENIED` for a destination that is no longer allowed.
- Tests: the rule table in `gateway/policy.rs` (name rules at every kind of non-public address, mixed answers, literal versus range) and `gateway/forwarder.rs`; the rule was
  broken once to see its tests fail. The Node host's resolved-address policy and its fake-resolver tests (`test/gateway-address-policy.test.mjs`) are unchanged.

### Password hashing helpers for the Node host; `wsh-server hash-password` (additive)

- **New, `@johnhenry/wsh/server`:** `hashPassword(password)`, `verifyPassword(password, stored)` and `passwordVerifier(hashes, { allowLegacySha256, onWarn })`. A password is stored as a
  PHC string `$scrypt$ln=16,r=8,p=1$<salt>$<hash>` (scrypt from `node:crypto`: memory-hard, 64 MiB by default; a random per-user salt; `timingSafeEqual`; the cost parameters of a stored
  value are bounded). `passwordVerifier` is an `auth.password` callback over a table, a `Map` or a lookup function: an unknown user costs the same derivation as a wrong password, and an
  entry that is not one of these hashes is refused with a warning that names the user and never the value. An unsalted `sha256:<hex>` entry is refused, as `wsh-server` refuses it, unless
  `allowLegacySha256: true`, which verifies it in constant time and warns naming the user. `auth.password` itself is unchanged: any `(username, password) => boolean` still works.
- **New, Rust `wsh-server`:** `wsh-server hash-password` is a subcommand (the `--hash-password` flag still works). The password is read from standard input, or prompted for without echo (and
  repeated) at a terminal; it is never an argument. `dialoguer`, already in the dependency tree through `wsh`, is now also a `wsh-server` dependency.
- A host that lives in a page keeps its own `auth.password` callback: WebCrypto has no scrypt or Argon2, so nothing is added to the browser-safe entry points; the README says what to use there.
- **Wire:** none. **A released peer:** nothing is negotiated; the Rust server's Argon2id strings and these scrypt strings are not interchangeable and neither side reads the other's.
- Tests: `test/server-password-hash.test.mjs` (PHC shape and salts, right and wrong passwords, malformed and oversized stored values, the same derivation for an unknown user, the legacy
  entry refused and allowed, a real login over `createWshServer`), and a clap test that `hash-password` takes no password argument. The unknown-user rule was broken once to see its test fail.

### Fix: `wsh-server` could lose WebTransport control messages when a frame arrived in pieces (Rust)

The post-login loop of a WebTransport connection waited for the next length-prefixed frame with a read that is not safe to abandon. When another event (a reply to push, a shutdown) was ready while a frame was half read, the bytes already taken were thrown away and the stream was out of step from then on, so later messages were misread or never arrived. It showed under load with frames larger than a packet (a 5000-byte UDP payload on the control stream, the test `udp_datagrams = false keeps every flow on the control stream`). The frame is now accumulated across reads, so nothing read is lost. No wire change.

### CBOR codec: a decoded map is plain data, and every finite number round-trips (JS; `src/cbor.mjs`)

- **A decoded map's keys never change what the object inherits.** The decoder used to assign `obj[key] = value`, so a map key `__proto__` ran the prototype setter and gave the decoded object another prototype. Entries are now
  own data properties: a `__proto__` key is an ordinary own member (definite- and indefinite-length maps, nested maps), and `constructor` / `prototype` / `toString` were already ordinary own members and still are. The rpc
  message copy (`prune` in `src/rpc.mjs`) copies such a member the same way. The Rust codec has no prototypes and needs no change.
- **The encoder writes every finite double so that it decodes to the same number.** An integral double at or beyond 2^64 in magnitude (for example `1e21`) was written as a wrapped 64-bit integer and decoded as a different number; `-0` was
  written as the integer 0; a negative integer below -2^53 decoded one step off. Now: integral values within the uint64 / nint64 ranges stay integers (exactly, from a BigInt past 2^53, as before for those that were exact), and anything else
  (a fraction, `-0`, NaN, an infinity, an integer at or beyond 2^64 in magnitude) is a float64. NaN and the infinities were already floats.
- **Wire:** none new; the bytes of every value that round-tripped before are unchanged. **A released peer:** a released JS peer reading a float64 where it used to read a wrapped integer gets the correct number; a released Rust peer
  decodes float64 as it always has (a Rust test asserts the boundary vectors).
- Tests: `test/cbor-hardening.test.mjs` (own `__proto__` key, both map forms, nested, through `FrameDecoder`; a table of doubles across 2^53, 2^63, 2^64, 1e21 and their negatives, `-0`, NaN, infinities, and the exact boundary bytes) and a `wsh-core`
  codec test with the same vectors. The map rule and the integer rule were each seen failing before the change.

### Rust dependencies: `rustls` 0.23.46 (lockfile only)

`Cargo.lock` moves `rustls` from 0.23.41 to 0.23.46 (with `rustls-webpki` 0.103.17, `aws-lc-rs` 1.19.0 and `aws-lc-sys` 0.47.0 that it brings), the patched version of four open dependency alerts. No source or wire change; the Rust binaries of the next `rust-v` release carry it.

## 0.45.0 / Rust `rust-v0.16.0`

### Rust `wsh-server`: UDP flows as WebTransport datagrams, `gateway-datagram` (#124, #145, the last open item of the parity epic; Rust only)

`wsh-server` now serves `OpenUdp` flows as WebTransport datagrams, as the Node host does (0.38.0), behind the same feature string. **No new wire message and no new
feature string**: `gateway-datagram` is the existing one (`src/gateway-datagram.mjs`), listed by the server in `ServerHello.features` **only on a WebTransport
connection, with `[gateway] enabled = true` and `udp_datagrams` not `false`**, and used per connection only when the client lists it in `Hello.features` too.

- **Layout, as on the Node host:** the whole QUIC datagram payload is `[gateway_id u32 big endian][UDP payload]`; `OpenUdp`, `GatewayOk`/`GatewayFail` and
  `GatewayClose` stay on the control stream, `GatewayCredit` does not apply to a datagram. A datagram that is malformed, names a flow the connection does not have, or
  arrives before authentication, is dropped.
- **Size:** the limit is read from the QUIC connection for every payload (`max_datagram_size`, minus the 4-byte id), not assumed. A reply that does not fit goes on the
  control stream as `GatewayData` (the default, `udp_oversize = "reliable"`), or is dropped (`udp_oversize = "drop"`); a payload the client sends on the control stream
  still reaches the origin. A payload over 65507 bytes is ignored, as before.
- **The bounds of #145 apply to both paths:** the per-flow, per-client and byte buckets, `udp_max_flows` and the idle limit (a datagram in either direction counts as
  activity) are the same code for a datagram and for a `GatewayData`.
- **Config (new, `[gateway]`):** `udp_datagrams` (default `true`: **a WebTransport client that lists `gateway-datagram` now gets its UDP flows on datagrams where it
  was served on the control stream before**; set `false` to keep the old behaviour) and `udp_oversize` (`"reliable"`, the default, or `"drop"`).
- **What a released peer does:** a released `wsh-server` never lists the feature, so any client keeps the control stream against it. A released JS client (it has
  listed the feature since 0.38.0, on WebTransport only) now gets datagrams from this server over WebTransport, as it does from the Node host; a client that does not
  list it (any older client, or a WebSocket one) is served on the control stream exactly as before. The Rust `wsh` client has no UDP flows.
- **Not done:** `gatewayStats()`-style counters (drops are logged at `debug`); a browser (Chromium) against the Rust server (the Playwright test runs against the Node host).
- Tests: `test/rust/wsh-rust-server-udp-datagrams.test.mjs` (the JS client over a real QUIC session against the binary: negotiation, round trip, the size limit both ways,
  `udp_oversize`, `udp_datagrams = false`, a WebSocket client, the bounds on the datagram path); unit tests in `wsh-core` (`gateway_datagram`, the same vector as
  `test/gateway-datagram.test.mjs`), `udp_policy` and the gateway session (a fake transport). Each rule was broken once to see its test fail.

### Rust-suite flakes (#162, part; tests only, no change to any released code)

- `test/rust/wsh-rust-server.test.mjs`, "a principal granted access via grantSessionAccess attaches with no token at all": a `SessionGrant` has no acknowledgement
  (the server answers only an error) and `sendControl` resolves when the frame is written, so the grantee, who connects on another connection that the server serves
  independently, could attach before the grant was applied ("not authorized to attach to this session"). Reproduced by delaying the grant in the server by 1.5 s; the
  test now waits for the answer to a request sent after the grant (a connection's control messages are handled in order). The server needed no change: it applies a grant
  before it handles the next message.
- `test/rust/wsh-rust-server-forwarding.test.mjs`, "serves many concurrent connections and enforces max_connections", which once hung to the 180 s timeout: not reproduced
  in about 45 runs (serial, in parallel, throttled). A stalled transfer now fails after 30 s naming the connection and how far it got.

### Rust `wsh-server`: reverse tunnels and UDP flows get the Node host's bounds (#145, part; Rust only; **breaking defaults, read this**)

The two rows of the README capability matrix that said "Rust still needs ... the same bounds" are done. **No wire change, no new feature string, nothing
changes for a client**; the Rust server now refuses and closes where the Node host (`gateway.reverse`, `gateway.udp`) already did, with the same defaults and the
same refusal sentences (`ListenFail.reason`, `GatewayFail.message`). `wsh-server` only; a released `wsh` and a JS client see a refusal they already know how to read.

- **BREAKING (defaults), TCP reverse tunnels** (only where `[gateway] enable_reverse_tunnels = true`):
  - `reverse_ports` (new; default `[0, "1024-65535"]`). A `ListenRequest` for a port below 1024 is now refused with `port 80 is not allowed by the
    reverse-tunnel policy (ports below 1024 must be listed explicitly by the host operator)`. A deployment that listened on a privileged port must list it
    (`reverse_ports = [80, 0, "1024-65535"]`); a list REPLACES the default, so name what you want. Entries are integers and `"lo-hi"` ranges; a bad one stops start-up.
  - `reverse_max_listeners` (4 per client connection; before, only `max_connections` bounded them), `reverse_max_connections_per_listener` (16; the next
    connection is closed and never announced), `reverse_backlog` (8, now really passed to `listen(2)`; at least 1), and `reverse_idle_secs` (300; before, a quiet
    tunnel stayed open for ever; `0` keeps that). The idle limit watches a connection the relay is reading; one parked waiting for the client's credit is bounded
    by the credit window and the caps instead.
- **BREAKING (defaults), UDP flows (`OpenUdp`) on the reliable control stream:** `udp_max_flows` 16 per client connection (`too many UDP flows (limit N)`,
  `GatewayFail` code 7), `udp_packets_per_second_per_flow` 500 and `udp_packets_per_second_per_client` 2000 (token buckets over datagrams), and
  `udp_bytes_per_second_per_client` 4 MiB (payload bytes; this is the amplification bound), all counted in BOTH directions; a datagram over a limit is dropped,
  as a congested network would. `0` on a rate means no limit. `udp_idle_secs` (60, at least 1) now counts datagrams in either direction (it counted only replies,
  so a flow the client kept sending on, with no answers, closed at 60 s). A client that pushed more than 2000 datagrams a second through one connection now loses
  the excess.
- **Still not in the Rust server (`gateway-datagram`):** UDP as WebTransport datagrams (the `[gateway_id u32 BE][payload]` layout, `maxDatagramSize`, the
  oversize choice). A client that lists the feature to a Rust server keeps the reliable path, as with every released server. Left in the README matrix.
- **A released peer:** none of this is negotiated. A released JS client and `wsh` keep working and see the refusals above; a released `wsh-server` keeps the old
  unbounded behaviour.
- Tests: `test/rust/wsh-rust-server-reverse.test.mjs` (the Node host's reverse cases against the real binary: the default and a given port list, start-up refusals,
  the listener cap, the per-listener cap and its slot coming back, the idle limit with and without traffic, `0`, and listeners ending with the client) and
  `test/rust/wsh-rust-server-udp-bounds.test.mjs` (flows, the three rates, amplification with small queries and big answers, `0`, idle in both directions);
  unit tests for the policies, the token bucket and the connection wrapper. Every new rule was broken once to see its test fail.
- Out of scope for the Rust server, listed for #145: named endpoints (`OpenEndpoint`) and execution targets (`ListTargets`) are for hosts without a file system and
  are not offered by `wsh-server` (they parse and grant nothing, README); `tls-exporter` channel binding needs a TLS terminated by the process itself.

### `wsh mcp`: the Rust CLI bridges stdio to the `mcp` rpc channel of a host, on a new rpc client in `wsh-client` (#127, the Rust half; Rust only)

The other half of #127 (the npm `wsh-mcp` shipped in 0.44.0). `wsh mcp [user@]host|URL` lets an MCP client that launches a command use an MCP server
behind a Node host or a memory host, without Node. **No wire change, no new feature string, no default changed**: the channel is #85's, and a Rust
`wsh-server`, a released JS host and a released Rust client are all untouched. The one spec edit lists `rpc` among the `ChannelKind` values the
`Open` message already carried (`Open { kind: "rpc" }` has been on the wire since #85; the Rust server reads it from the raw message), so the Rust
types now have a name for it; the generated JS and Rust files and `spec/wsh-v1.md` follow, which adds one export to the npm package, `CHANNEL_KIND.RPC`
(`'rpc'`, typed in `index.d.ts`; nothing in the package uses it yet, and the `has exactly 7 kinds` test now says 8).

- **`wsh-client` gets an rpc client.** `WshClient::open_rpc(protocol)` sends `Open { kind: "rpc", command }` (refused before anything is sent when
  the host did not advertise `rpc` and `rpc-protocol:<name>`), opens the channel's data stream and returns an `RpcChannel` that sends and receives
  JSON-RPC messages as a CBOR sequence, bounded by the host's `rpc-max-message:<n>` both ways (`rpc_offer()` reads the offer). To make that possible
  the WebSocket transport can now open a client-initiated QMux data stream (it returned an error before) and announces it with an empty STREAM frame,
  as the JS client does (`QMuxConnection::announce_stream` in `wsh-core`); streams are opened without the transport lock, which the dispatch loop
  holds while it waits. The CBOR-sequence decoder (`wsh_core::rpc_codec`) is the one `wsh-server` already uses for the channels it hosts, with the
  same bound and the same refusals (copied rather than shared: `wsh-server`'s own decoder is untouched).
- **`wsh mcp` behaves as `wsh-mcp` does**: stdout carries MCP messages only, one per line; `--channel NAME`; reconnect (5 attempts from 500 ms,
  doubling; `--reconnect-attempts`, `--no-reconnect`) that replays `initialize` / `initialized` without telling the client; a request in flight when
  the connection drops is answered with `-32603`; what the client sends meanwhile is held (at most 200, the rest of the requests refused);
  `notifications/cancelled` for a request in flight becomes the channel's `$/cancel`, and the answer to it is not passed on; exit 0 when the client closes,
  1 when the host is lost for good, 2 when it cannot start, including **a host that offers no such channel, with the channels it does offer**.
- **Differences, on purpose:** the identity is `-i NAME` (a key in `~/.wsh/keys`, what `wsh keygen NAME` writes), not a file; without `--host-key` the host
  is checked against `known_hosts` like every `wsh` command (a first use is refused without `--accept-new-host-key`: stdin is the MCP stream and cannot
  answer a prompt). `--host-key KEY` (64 hex digits or an `ssh-ed25519` line) pins the host through a new `ConnectConfig::expect_host_key`: the host must
  prove that key before any credential is sent, a host that proves none is refused, and `known_hosts` is neither read nor written. `--via` works. `--target`
  is refused, as for every command that is not per target.
- **`wsh-server`:** it serves `wsh-host` (and `wsh-fs` with `[rpc] fs_root`) and **no `mcp` channel**, so `wsh mcp` to it is refused (exit 2, "it offers:
  wsh-host") rather than working; `wsh tools` is the way to its `[[mcp.tools]]`. `wsh mcp --channel wsh-host` against it works, and is tested.
- **A released peer:** a JS host serves `mcp` over rpc since 0.25.0 (`mcpServerAdapter`); a released Rust client cannot open rpc channels at all (it has no
  `open_rpc`), and does not need to change; a host without `rpc` is refused before anything is sent.
- Not covered: a sealed session carries no rpc channels on any host (`wsh mcp --sealed` is refused); WebTransport opens the stream but is untested against a
  host (the peer sees a WebTransport stream only at its first byte, which the first message supplies).
- Tests: `test/rust/wsh-mcp.test.mjs` drives the built `wsh` with the MCP SDK's stdio client against a Node host and a memory host, and covers the same cases
  as `test/mcp-stdio.test.mjs` (no channel, `--channel`, refused login, pinned and unpinned host key, reconnect, give-up, the held bound, cancellation, signals,
  the size limit, `--via`), plus `wsh-server`; unit tests in `wsh-core` (`rpc_codec`, `announce_stream`), `wsh-client` (`rpc`) and `wsh-cli` (`mcp`).

## 0.44.1

### The README states the gzipped size of each browser entry point, and CI fails when it is stale (#128, the part that was left; tooling and docs only)

Most of #128 was already in place (#115, #131, #138): `"sideEffects": false`, separate browser entry points for the client (`.`), the memory host
(`./memory`), the connection pieces (`./host`) and the reverse host (`./reverse`), the CBOR codec and the generated tables tree-shake (probes
bundle a single import), `npm run size` bundles each entry with esbuild and compares it to `scripts/bundle-budget.json` (CI runs it, writes the
table to the job summary, and a bundle more than 10% over its budget fails), and `test/browser-bundle.test.mjs` rejects a Node built-in or
`Buffer` in any of them. What was missing: the README did not state the sizes. It now has a table (minified and gzip bytes of each entry point
and of three single-import probes) between markers, rendered from the budget file; `npm run size -- --update` rewrites budget and table together,
and `npm run size` (CI) and `test/browser-bundle.test.mjs` fail when the table is not the budget's. No change to the package, no wire change.

### Spec versus implementation: a generated message matrix, and a compatibility policy (#129; documentation and tooling, no wire change)

- **`spec/message-matrix.md`** lists every message of `spec/wsh-v1.yaml` (110) and whether the JS host, JS client, Rust host and Rust client
  name it (send it or act on it in code that is neither generated nor a test). It is **generated** (`npm run matrix`) from the spec and from the
  source of each implementation: `MSG.X` or a call of the message's builder in `src/`, `Payload::X` / `MsgType::X` / `XPayload` in `crates/`,
  comments and `#[cfg(test)]` code removed. `npm run matrix:check` (a CI gate, and `test/message-matrix.test.mjs` in `npm test`) fails when the
  file is stale, and when a source file is not classified as host, client or shared in `scripts/message-matrix.mjs`. It says that a handler
  exists, not that every field is honoured. At the time of writing 62 messages are named by all four and one (`AuthMethods`) by none.
- **`COMPATIBILITY.md`**: what a release may change before 1.0, optional fields on decode, what a released Rust peer (`deny_unknown_fields`)
  does with a field it does not know and what a released JS peer does (ignores it), feature strings gating anything a released peer would
  reject or silently ignore, fail-closed parsing of options (the `capabilities=` hazard on released Rust servers), defaults deny.
- Not done from the issue: a per-message `implemented:` status inside the spec file itself (it would be a hand-kept second source of truth
  that the generated matrix replaces), and the "ideas" file for messages that are not planned (what is planned is the owner's call; the matrix
  lists the messages nobody names).
- No wire change, no feature string, no default changed, no generated file touched.

### Fix: a sealed reverse bridge no longer drops an operator's first frame that outruns the host's key derivation (#162)

`test/operator-proof.test.mjs` ("injects an Open stamped with the operator's fingerprint ...") failed now and then with
`Timed out waiting for session open response` (1 of 20 on macOS, once on Linux CI). The cause was in `createReverseHost`, not the test:
the operator seals its first message the moment ITS half of the key exchange is done, and when the operator encapsulates (which side
does depends on the two ephemeral keys) the host still has to decapsulate the ML-KEM ciphertext and combine the secrets. A first frame
that reached the host in that window found no key yet and was dropped as "not sealed", so the `Open` was never answered. The host now holds
bridge-level frames of the bridge's session that arrive after the key exchange began (at most 16, opened in order once the key exists, discarded
if the exchange fails). Frames before any `KeyExchange`, for another session or in excess are still dropped; a plaintext message on a bridge
that must be sealed is still dropped; nothing is sent differently, so no wire change, no feature string, no default changed.
Regression test: a hostile hop that makes the order certain (it delivers the operator's first frame ahead of its ciphertext) fails on 20 of 20
runs before the fix and passes 20 of 20 after.

## 0.44.0 / Rust `rust-v0.15.0`

### `wsh-mcp`: a stdio bridge so MCP clients can reach an MCP server behind a wsh host (#127, partial; JS only)

An MCP client that launches a command and speaks MCP over stdio can now use the tools of a server behind a Node host or a memory host. The
package gains a `bin`, **`wsh-mcp`**, and a module, `@johnhenry/wsh/mcp-stdio` (`runMcpStdioBridge`, `loadIdentity`, `McpBridgeError`).
**Nothing changes for anyone who does not run it**: no wire change, no new feature string, no default changed, the package root and the
browser bundles are untouched.

- `wsh-mcp [options] [user@]<url>`: connects (a `ws://`, `wss://` or `https://` URL), logs in with an Ed25519 key (`--identity`, default
  `~/.wsh/keys/default.pem`, the file `wsh keygen` writes; a PKCS#8 PEM works too), opens the host's `mcp` rpc channel (`--channel NAME`
  for another) and passes the JSON-RPC messages both ways, one per line, verbatim (ids, notifications, progress, `notifications/cancelled`).
  `--host-key` pins the host (it warns on stderr when unpinned). stdout carries MCP messages only.
- A host that offers no such channel is a clear error (exit 2) that lists the channels it does offer and how to serve one. Other exit
  statuses: 0 the client closed stdin, 1 the host was lost for good.
- After a dropped connection it reconnects (`--reconnect-attempts`, default 5 from 500 ms, doubling; `--no-reconnect` exits instead),
  re-sends the client's `initialize` / `initialized` to the new channel without telling the client, answers a request that was in flight
  with a JSON-RPC error (`-32603`) and delivers, once it is back, what the client sent meanwhile (at most 200 messages). Serve a factory
  (`mcpServerAdapter(() => makeServer())`) so a second channel is served.
- A malformed line is answered with a JSON-RPC error (`-32700` / `-32600`) and the bridge goes on; a message over 8 MiB is refused.
- **Not done, and why:** the issue also asks for `wsh mcp` in the Rust CLI. `wsh-client` has no rpc channel (README capability matrix), so a
  Rust `wsh mcp` is a client feature of its own; not built here. `--target` is not offered: rpc channels are not per target on any host
  (#121), and `wsh-mcp --target` says so.
- **A released peer:** the bridge speaks the `rpc` channel (#85) that a JS host serves since 0.25.0 (mcp over rpc as a host option: `mcpServerAdapter`); a released Rust
  `wsh-server` offers no `mcp` rpc channel (only `wsh-host` / `wsh-fs`), so `wsh-mcp` to it exits 2 with that message.
- Tests: `test/mcp-stdio.test.mjs` runs the command as a child process with the SDK's `StdioClientTransport` against a Node host and a
  memory host, and covers the no-channel, refused-login, pinned-host-key, reconnect, signal and size-limit cases.

### `authorized_keys` options: the same key file gives the same answer on both hosts (#122, step one; JS and Rust change)

The Rust `wsh-server` has read `restrict`, `permit-*`, `no-pty`, `command=` and `max-sessions=` from `authorized_keys` since the
start; the Node host skipped every line that began with options, so `restrict,permit-exec ssh-ed25519 ...` parsed to no key there
(failing closed, but not the same answer). Now both read the same syntax with the same rules, enforce the same options at their own
entry points, and refuse a key whose options they do not understand. **No wire change**; no new option, feature string or message.
Capabilities, expiry and per-target/gateway scoping are step two.

- **Node host (`auth.authorizedKeys`, `createWshServer`, `createMemoryHost`):** lines with options are parsed (quoting: one options
  token, spaces only inside double quotes, `\"` for a quote). Enforced at `Open` (`pty`, `exec`, `file` = upload and download, `rpc`),
  `FileOp`, the rpc channels (`wsh-fs` needs file transfer, `mcp` needs MCP, `wsh-host` is open, another protocol only to a key that is
  not restricted), `McpDiscover` (an empty list) and `McpCall`, and the relay entry points `ReverseRegister` / `ReverseList` /
  `ReverseConnect` (a `ReverseReject` / `Error` with `relay not permitted for this key`). `command="..."` runs that command whatever
  the client asked for; `max-sessions=N` counts the key's live pty/exec sessions over all its connections. New:
  `parseAuthorizedKeyEntries(text)` (`{ entries, refused }`) from `@johnhenry/wsh/server`; `parseAuthorizedKeys` still returns bare
  keys, now only for lines without options (it never hands out a key with its restrictions dropped).
- **Unknown options fail closed, on both hosts.** An option that is not in the README table (`from=`, `permit-teleport`, a
  differently-cased name, ...), a malformed value or a stray comma keeps the key off the allowlist and logs the reason with a stable
  code (`unknown-option`, `bad-syntax`, `bad-value`, `duplicate-option`). Rust used to ignore an unknown option and grant the rest.
- **Shared test vectors:** `spec/key-options.vectors.json` (a key line gives these permissions; a request is allowed or refused with
  this code) is run by `test/key-options.test.mjs` and by `crates/wsh-server/src/auth/permissions.rs`; `test/rust/wsh-key-options.test.mjs`
  drives every line against the real `wsh-server`.
- **Rust `wsh-server` changes (lands in the next `rust-v` release), tightening only for keys that carry options:**
  - an option it does not understand now refuses the key (was: ignored);
  - `max-sessions=0`, `max-sessions=abc`, `command=""` refuse the key (were: ignored, i.e. no limit / forced empty command);
  - single-quoted values (`command='ls'`) refuse the key (were: quotes trimmed); a quoted value with a space (`command="a b"`) now
    works (the line was split at the first space and the key silently dropped); a tab may separate the fields;
  - `permit-mcp` and `permit-relay` are enforced (they were parsed and ignored): a `restrict` key without them gets no MCP tools
    and cannot register with, list or connect through the relay;
  - a forced-command key gets no `FileOp` (it was served `list`); `max-sessions` counts pty and exec opens only (file and rpc opens
    were refused too when the cap was reached);
  - **a key with any restriction can no longer install a key (`AuthorizedKeyAdd`)**: the installed line has no options, so a
    `restrict,permit-exec` or `command=` key could add an unrestricted key for itself.
- **Defaults:** a key with no options is unchanged on both hosts. **Breaking for a deployment that relied on the old Rust leniency**
  (a key line with an unknown option, `max-sessions=0`, single-quoted values) and for `restrict` keys that used MCP or the relay
  without `permit-mcp` / `permit-relay`. A Node host that used to see such a line as "no key" now serves it, with its restrictions.
- **A released peer:** nothing new crosses the wire. A released Node host skips every line with options (the key cannot log in), a
  released Rust server applies the options as before except as listed above. Clients are unaffected.
- Not covered (README, Security model): the gateway, targets and `AuthorizedKeyAdd` on the Node host (it has none) are not scoped per
  key; `no-port-forwarding` is accepted and does nothing.

### Per-key capabilities and expiry: `capabilities="..."`, `expires="..."` (#122, step two; JS and Rust change)

A key can now be given a finer, default-deny licence than `restrict` / `permit-*`: a capability list and an expiry, in its
`authorized_keys` line (the same file works on the Node host and the Rust `wsh-server`) or, on the Node host, as what `authorize()`
returns. Builds on the options of the entry above. **Nothing changes for a key whose line has neither option**, and no default
changes. **No wire change**: refusals use the answers each entry already has.

- **Grammar** (one, shared): `exec` `pty` `relay` `fs:read` `fs:write` `gateway:tcp:<host>:<port>` `gateway:udp:<host>:<port>`
  `gateway:listen:tcp:<port>` `unix:<path>` `unix:listen:<path>` `endpoint:<name>` `mcp:<tool>` `target:<name>` `rpc:<protocol>`;
  hosts may be `*` or `*.suffix`, ports and names `*`, paths exact or `/dir/*`. Once `capabilities` is present the key may do only what
  it names, ANDed with its other options. An unknown capability, a bad argument or a bad timestamp refuses the key with a logged code
  (`unknown-capability`, `bad-capability`, `bad-value`), like an unknown option. `expires` (RFC 3339, whole seconds) refuses the key at
  login and on every request after it.
- **Enforced** on the Node host at: `Open` (`pty`, `exec`, file upload/download, `rpc`), `FileOp` (read ops vs write ops), the gateway
  (`OpenTcp`, `OpenUdp`, `ResolveDns`, `ListenRequest`, `OpenUnix`, `ListenUnix`, `OpenEndpoint`), MCP (`McpDiscover` lists only the tools
  the key holds, `McpCall`), targets (`Open`, `FileOp`, `OpenEndpoint` naming one; `ListTargets` lists only the ones held), the relay
  entry points, and login. On the Rust server at every entry it has (all of those but endpoints and targets, which it does not have: it
  refuses `OpenEndpoint` and any request naming a target, whatever the key holds). The `wsh-fs` rpc channel needs both `fs:read` and
  `fs:write` (a client falls back to `FileOp`). A key with a capability list may not install a key (`AuthorizedKeyAdd`).
- **Node host API:** `authorize()` (in `auth` or as the `auth` function) may return `{ capabilities, expires }` instead of `true`: the same
  grammar, narrowing the key's own options. `onRefused` gains two stable reasons, `not-permitted` (every refused request; `detail` names the
  missing capability) and `key-expired`; `REFUSAL_REASONS` and the types list them. `KeyPermissions` gains `capabilities` and `expires`.
- **Shared vectors** (`spec/key-options.vectors.json`) now cover the grammar, every refusal and the matching rules (hosts, ports, paths,
  targets, expiry boundaries), run by `test/key-options.test.mjs` and `cargo test`; `test/server-capabilities.test.mjs` serves and refuses
  at every Node entry point; `test/rust/wsh-capabilities.test.mjs` does the same against the real `wsh-server`.
- **A released peer:** nothing new crosses the wire. A released Node host (0.43.0) skips a line with options, so such a key cannot log in
  there; a released Rust server (`rust-v0.14.0`) ignores `capabilities` and `expires` (unknown options), so it would serve that key
  everything -- **do not put these options in a key file read by a released Rust server** (the new one refuses a key with an option it does
  not understand, the old one does not). Clients are unaffected.
- Not covered (README, Security model): what a granted capability can reach; connections, commands and streams already open when a key
  expires; operations on a session the key already owns; password logins; a key file is read at start.

## 0.43.0 / Rust `rust-v0.14.0`

### Execution targets: `Open.target`, target discovery, `wsh --target` (#121; JS and Rust change)

A host that fronts several places to run things (containers, VMs, workers, sandboxes) can now say which one a request is for, instead of
overloading `username` or prefixing the command. **Nothing changes unless a host sets `targets`:** no feature is advertised, no existing
message or option changes meaning, and no default changes (not a breaking change).

- **Wire (spec change, regenerated):** optional `target` on `Open`, `FileOp` and `OpenEndpoint`; new `ListTargets` (`0xab`) and
  `TargetList` (`0xac`, with `TargetInfo { name, description?, capabilities }`); the feature string `targets` in `ServerHello.features`.
  A client sends a `target` (or `ListTargets`) only to a host that advertised `targets`. **A released peer:** the Rust types deny unknown
  fields, so a released Rust `wsh-server` would reject an `Open` carrying `target` -- which is why nothing is sent to a host that did not
  advertise the feature, and the new Rust server refuses (never ignores) a `target` it receives anyway. A released JS host would ignore
  `target` and run on its own default -- the same reason. A released client never sends any of it.
- **JS host (`createWshServer`, `createMemoryHost`, `createConnectionFactory` via `resolveBackends`):**
  `targets: { [name]: { description?, authorize?(who, { target, kind }), exec?, pty?, fs?, endpoints? } }` and `requireTarget`. Each target has
  its own backends (the same forms as the host's own; `exec: true` and `fs: { root }` on Node); a request that names no target uses the host's
  own, a target without a backend for the request refuses it, and `io.target` / `{ target }` in the pty and file-backend calls /
  `duplex.target` tell a shared function which target it serves. `authorize` is asked for every request that names a target and for
  `ListTargets`; a refused target and an unknown one get the same answer (`no such target`). `requireTarget: true` refuses an `Open`
  (including `rpc`), `FileOp` or `OpenEndpoint` that names none. `createReverseHost` takes no `targets` (it throws).
- **JS client:** `client.listTargets()`, `openSession({ target })`, `WshClient.exec(url, cmd, { target })`, `fileOperation(op, path, { target })`
  (a request with a target never goes over the `wsh-fs` rpc), `openEndpoint(name, { target })`; each throws before sending against a host that
  does not advertise `targets`. Types and `TARGETS_FEATURE` exported.
- **Rust CLI and client:** `wsh --target NAME [user@]host [command...]` and `wsh --target NAME connect`, `wsh targets [user@]host [--json]`;
  `SessionOpts.target`, `WshClient::list_targets()`, `TARGETS_FEATURE`. `--target` is refused (exit 2) by every other subcommand, by `-L`,
  `-R`, `-N` and `--share` (not per target), so it is never silently ignored; file and endpoint calls of the Rust client send no target.
- **Rust `wsh-server` has no targets:** it states no `targets`, answers an `Open`/`FileOp` that names one with a failure (`this host has no
  targets`) and `ListTargets` with an error.
- Not covered by a target (README, Security model): the gateway, MCP, rpc channels and `Attach` to an existing session; and a target is an
  authorization boundary only as far as `authorize` and the backends make it one.
- Tests: `test/targets.test.mjs` (two targets, a key refused on one, listing per key, `authorize` arguments, `requireTarget`, hosts without
  targets, malformed names, options), `test/rust/wsh-targets.test.mjs` (the Rust CLI against a JS host with two targets and against `wsh-server`),
  `wsh targets` rendering unit tests. Bundle budget unchanged (within the 10% tolerance).

### Rust relay and `wsh` peer: several operators per peer (#93; Rust change, no `src/` change)

The Rust relay (`wsh-server --enable-relay`) and the Rust peer (`wsh reverse`, `wsh agent run`) now do what the JS relay and
`createReverseHost` have done since 0.28 (#89). Lands in the next `rust-v` release. **Nothing changes unless you turn it on:**
default `1` operator per peer on the relay, `1` on the peer.

- **Relay: `[relay] max_operators_per_peer = n`** (1 to 64, default 1; there is no command-line flag). Above 1 the relay advertises
  `relay-multi-operator` in its `ServerHello.features`; only a peer that states the same feature in its `ReverseAccept.features`
  is bridged to several operators, any other peer stays at one. It routes a peer's `RelayForward` by `to_fingerprint` (checks the
  inner like the JS relay does -- at most 8 MiB, decodes, a forwardable type -- and delivers it re-wrapped with the peer's own
  authenticated key, never with `to_fingerprint`), drops a forward it cannot address (an unknown operator, or none while two or
  more are bridged), and sends a peer that serves several a `ReverseClose { target_fingerprint, reason }` when one operator leaves
  instead of ending anything.
- **Relay, in every configuration: `e2e-sign` is advertised** in `ServerHello.features` (the relay already carried
  `KeyExchange.signature`), so a JS `createReverseHost` now signs its half of an end-to-end exchange through a Rust relay
  (before, it waited for a feature the Rust relay never listed).
- **Relay, in every configuration: one request at a time, with reasons.** A second `ReverseConnect` to a peer that is bridged (and
  cannot take more) or is answering another request, or from an operator that already has a bridge or request, is now answered by
  the relay with a `ReverseReject` carrying the JS relay's `busy:` reasons; before, it was forwarded and the peer refused it, and
  the relay's bookkeeping could point two operators at one peer. A request nobody answers stops blocking the peer after 8 s. Only
  the peer a request went to can answer it (a `ReverseAccept` from the operator side used to be forwarded to the peer).
  `ReverseAccept.features` is bounded (at most 64 entries of at most 128 bytes) before it is read.
- **Peer: `--max-operators n`** (global flag of `wsh`, default 1, 1 to 64, for `wsh reverse` and `wsh agent run`). On a relay that
  advertises `relay-multi-operator` the peer states it in `ReverseAccept.features`, serves each operator with its own runtime
  (channels, processes, files, MCP, gateway state), addresses every message to the operator it answers
  (`RelayForward.to_fingerprint`), takes each operator's `--allow-operator` and operator-proof decision on its own, and ends one
  operator's work (processes killed) on `ReverseClose` while the others carry on. On a relay that does not advertise it, the
  flag changes nothing. **Not supported with several operators: sealed bridges** (the connection holds one seal), so
  `--max-operators` above 1 together with `--require-operator-proof` is refused at start, and an operator that insists on
  `--sealed` is refused by such a peer.
- **Fix found on the way (affects every Rust host): a running command was not killed when its channel closed**, or when the
  operator went away. The kill took a lock the task that waits for the child holds until the child exits, so it waited for the
  very process it was to kill, and the host stopped serving until the command ended by itself. It now kills through a separate
  handle.
- **A released peer or relay:** a multi-operator relay sends `ReverseClose` and addresses nothing to a peer that did not state
  `relay-multi-operator`, so a released Rust peer (whose generated types reject unknown fields) never meets either; the relay never
  delivers `to_fingerprint` to anyone; a new peer sends `to_fingerprint` only to a relay that advertised the feature, which a
  released Rust relay (it drops a connection that sends the field) never does. A released operator sees nothing new except the
  `busy:` `ReverseReject` where it used to get the peer's own refusal. Differences kept from the JS relay so nothing existing
  changes: when an operator leaves a one-operator peer the Rust relay leaves the peer connected, and a peer that goes away leaves
  its operators connected.
- Tests: `crates/wsh-server/src/relay/bridges.rs` (the bookkeeping, unit tests), `[relay]` config tests, and
  `test/rust/wsh-relay-multi-operator.test.mjs` (the Rust relay with JS peers and operators, the Rust peer on the Rust and the JS
  relay, `wsh agent run`, the default relay, a peer that stated nothing, the refused combinations, the kill fix). README:
  reverse mode, the capability matrix and the Security model.

### Tests: two failures on macOS, and `{ timeout }` passed to the gateway opens

No wire change, no default changed, no behaviour change in the shipped code; the Rust server's `wsh-fs` `list` order is now documented.

- **Rust `rpc::fs::tests::list_is_sorted_and_typed`** created `b` and `B`, which are one file on a case-insensitive filesystem (macOS, Windows), so the
  test failed there. The code was right and the test wrong: a listing is sorted by name in UTF-16 code-unit order (the JS host's `Array.sort()`, so upper
  case before lower case) on every platform, never in the filesystem's order. The test now uses names that do not differ only by case, and the
  README's `wsh-fs` row and the `list` doc comment state the order.
- **`test/rust` McpCancel "stops a long-running tool mid-way"** read `/proc/<pid>/stat` to tell whether the tool was running, and there is no `/proc`
  on macOS, so every process looked dead ("running before the cancel" failed). It now asks `ps -o stat=`, which works on Linux and macOS.
- **`{ timeout }` to `openEndpoint`** in `test/session-seal*.test.mjs`, `test/host-refused.test.mjs` and `test/rust/wsh-session-seal.test.mjs` was
  ignored (the option is `timeoutMs`), so those refusals waited the 10 s default. Fixed, and `test/test-hygiene.test.mjs` fails on the same mistake
  in any gateway open/listen call under `test/`.

## 0.42.0 / Rust `rust-v0.13.0`

### Rust `wsh-server`: seal a whole session end to end, `[server] seal_session` (#155 stage c, part 2; Rust change)

The Rust server can now be the responder of the sealed session of stage b, so a relay that only copies bytes (a pipe relay, a
TLS-terminating proxy) cannot read or alter a session with it: control messages, exec/pty data and gateway data all travel as
`EncryptedFrame`s once the key exists. Lands in the next `rust-v` release; no wire change (stage b's features and messages).

- **`[server] seal_session = "off" | "offer" | "require"`**, default `off`: nothing is advertised and no released client is affected
  (not a breaking change). `offer` and `require` need `[server] host_key` (refused at start otherwise). On a WebSocket connection the
  server advertises `e2e-session` (and `e2e-session-required` with `require`); after a KEY login it answers the signed key exchange (it
  verifies the login key's signature over both ephemeral keys and its own identity, signs the reply with the host key, hybrid
  X25519+ML-KEM-768), and from then on every control message but ping/pong is a frame both ways. A frame that does not open (flipped
  bit, replay, reorder) closes the connection; a plain message after the key exchange is dropped.
- **`offer`** serves a client that never asks exactly as before; **`require`** serves nothing in the clear: a plain message before the
  key exists is answered with an error and the connection is closed, a password login is refused ("needs a key login"), and
  **WebTransport connections and WISP guest tunnels are refused** (a sealed session is a WebSocket one; there is no unsealed back door
  to a `require` server). WebTransport on an `offer` server is served as before and does not list `e2e-session`.
- **Typed rpc channels (`wsh-fs`, ...) are not offered while `seal_session` is on** (they ride client-opened data streams, which are
  not frames); the server logs a warning at start. This is the one thing `offer` takes away from a client that does not seal.
- Implementation: `wsh-server` now depends on `wsh-client` for `SealGate`, `E2eResponder` and the sealed bridge (one implementation, the
  one the CLI uses); `SealGate::begin_session_responder` is new, and `incoming_direct` answers a responder's key exchange. Every write to
  the control stream of an authenticated WebSocket connection goes through `write_control` (the gate), in order.
- README: the sealed-session section, the capability matrix and the Security model. Not covered, as for the JS host: the handshake
  before login, sizes and timing, a denial of service; `offer` is not a downgrade guarantee (only a client that insists, `--sealed` /
  `sealSession: true`, is guaranteed; against `require` a stripped client is refused but what it sent before was readable).
- Tests: `test/rust/wsh-session-seal-server.test.mjs` (the real `wsh-server` behind a recording / tampering relay, driven by the JS
  client and by the Rust CLI: no plaintext marker or destination on the wire, flipped bit both ways, replay, plain injection both ways,
  bad key-exchange signatures, stripped features, an old client against `offer`, `require` refusing an old client, a password login and
  WebTransport); `seal_gate.rs` and `config.rs` unit tests. Each new rule was broken once and its test seen to fail.

### JS client: seal a whole session end to end, `connect(url, { sealSession })` (#155 stage c, part 1; npm change)

Stage a (#157) sealed the Rust bridge and stage b (#158) gave the JS host `sealSession: 'offer' | 'require'` and the Rust CLI the
initiator side. The JS client could not take part: against a host that requires sealing it was refused, and it could not seal a
pipe-relayed session at all. It can now. No wire change: the messages and feature strings (`e2e-session`, `e2e-session-required`) are
stage b's.

- **`sealSession: false | 'auto' | true`** on `client.connect()` (and so `WshClient.exec()`, `connectWithTransport()`). After login, before the keepalive starts
  and before anything is handed back, the client sends the signed hybrid `KeyExchange` for the connection's session id (login key signs
  its half, the host's PROVEN key signs the other: `initiateE2E` with `verifyPeer` / `signAs` / `responderIdentity`), then every
  message but ping/pong leaves as an `EncryptedFrame` on channel 0, in order. Nothing but the key exchange is sent before the key exists.
- **Receive side:** a message from the host that is not a frame of the session is dropped (only the keepalive is heard plain; before the
  key exists, only the key exchange). A frame that does not open (flipped bit, replay, reorder, forged) is fatal: `onError`, then the
  transport closes and `onClose` fires. A plain message injected by the relay does not close the session, it is not heard.
- **Default `'auto'` (a behaviour change, not a break):** seals only against a host that says `e2e-session-required`. A client that
  never heard of the option keeps talking plainly to a host that merely offers sealing, and a host that requires it, which used to
  refuse the JS client, now serves it sealed. `false` restores the old behaviour exactly (a requiring host then serves it nothing).
  `true` seals or fails BEFORE a credential is sent: a host that does not offer `e2e-session`, one that proved no host key, or a password
  login is refused with a sentence. Only `true` is a guarantee (`'auto'` rests on a ServerHello feature a relay can strip).
- `client.sessionSealed`; `openStream()` is refused and datagrams are neither sent nor heard on a sealed session (their bytes are not
  frames); `index.d.ts` and `test/types/identity.ts` carry the option.
- Fix on the way: a gateway channel's best-effort `GatewayClose` / `GatewayCredit` are now caught, since on a sealed session the send
  finishes after sealing and could surface as an unhandled rejection when the connection closed meanwhile.
- README: the sealed-session section, the capability matrix and the Security model say what this covers and what it does not (the
  exchange authenticates the key the host proved, not whose it is: pin it; the handshake before login stays readable; a relay can still
  drop or cut). The bundle grows about 0.7 kB gzip in `.`, `./memory`, `./reverse` (budget updated by hand from the measured delta).
- Not done (PR 2 of this stage): the Rust `wsh-server` does not offer `e2e-session` yet, so a JS client's `true` against it is refused.
- Tests: `test/session-seal-client.test.mjs` (a recording relay finds no plaintext marker and no endpoint name; a tampering relay in each
  direction, a replaying relay, injection of plain messages both ways, a relay answering the exchange with a bad signature, a stripped
  feature, a pinned-key mismatch, `true` refused before any `Auth` is sent); each new rule was broken once and its test seen to fail.
  `test/session-seal.test.mjs` now opts the client out (`sealSession: false`) where it tests the host's refusal of a plain client.

## 0.41.0 / Rust `rust-v0.12.0`

### Shares carry each folder's root path: `ShareOffer.paths`, `fs.root`, `--share-hide-path` (#164) (npm change)

A host that is asked for an absolute path (a Docker bind mount `-v /abs/dir:/in`) can now tell which share it belongs to, instead
of reading a hash the operator put in the share name. Optional field, no feature string needed, no default changed.

- **Wire** (`spec/wsh-v1.yaml`): `ShareOffer` gains optional `paths: string[]`, parallel to `shares` (each share's root as the
  operator typed it, made absolute and tidy). Optional on decode in JS and Rust. A client of 0.40.0 / `rust-v0.11.0` sends none; a
  0.40.0 host ignores the field it does not know.
- **CLI** (`rust-v` release): `wsh --share` sends the paths; `--share-hide-path` omits them. The path of `--share` is now made
  tidy (`//`, `.` and a trailing `/` removed) before the directory is opened.
- **JS host** (npm): `WshShareFs.root` (string or `undefined`). Validated: an array as long as `shares`, each entry an absolute
  string of at most 4096 bytes without NUL; anything else is `undefined`, never an error. `onShare` keeps its signature.
- **Advisory.** The host cannot verify the path and the CLI still serves only the directory it opened; stated in the README (Security
  model) and the types.
- Tests: `test/shares.test.mjs` (validation table, offer without the field), `test/rust/wsh-cli-share.test.mjs` (the real CLI:
  `fs.root` equals the shared directory, `--share-hide-path`), `crates/wsh-cli/src/sharefs/tests.rs` (tidy path, offer with and
  without paths, old-shape decoder).

### Rust CLI: `wsh scp` speaks `FileChunk`, like every host (#140) (Rust CLI and `wsh-client`)

Rust workspace and tests only (no `src/` change, no wire change); lands in the next `rust-v` release. Hosts are unchanged.

- **Fix.** The Rust client's `file_transfer::download` sent a header and read a raw stream (an 8-byte size, then the data), and
  `upload` wrote a header and the data as session bytes and waited for an acknowledgement that way. No host speaks that: the JS
  hosts (Node, in-page) and `wsh-server` carry a file as `FileChunk` control messages (offset-addressed, the last `is_final`) and
  end an upload with `Exit` and `Close`, as the JS client does. So `wsh scp` hung (JS hosts) or failed (`wsh-server`). The client
  now speaks `FileChunk` both ways: `WshSession::write_file_chunk`, `read_file_chunk` and `wait_closed` are new, `FileChunk` is
  routed to its session, and the download checks what the host sends (announced size, chunks in order, the last one reaches the
  size; a refusal is an `Exit` with a non-zero code and no chunk; memory reserved up front is capped at 64 MiB whatever the host
  claims). The raw-stream header builders are gone. An older `wsh` (`rust-v0.11.0` and before) still cannot `scp` from any host.
- README: the capability matrix's upload/download row and the in-page host row say so.
- Tests: `test/rust/wsh-cli-scp.test.mjs` (the real `wsh scp` up and down, 0 B / 17 B / 64 KiB / 300 KiB, a missing file, against a
  Node host through a pipe relay and against `wsh-server`: all 18 hung or failed before). The JS client's own upload and
  download against `wsh-server` was already in `test/rust/wsh-rust-server.test.mjs`.

### `onRefused` on the JS hosts; `wsh --version` prints the real version (#163) (npm and Rust CLI)

- **`onRefused({ reason, who, detail })`** (npm, additive, no wire change) on `createMemoryHost`, `createWshServer` and
  `createReverseHost` (and `cfg.onRefused` of `createConnectionFactory`): called once per connection the host turned away, with a
  stable code instead of a log line to parse. Codes (`REFUSAL_REASONS`, exported from `@johnhenry/wsh/host`; new ones may be
  added, none renamed): `not-sealed` (a plain client on `sealSession: 'require'` / `requireOperatorProof`), `unauthorized` (key
  not allowed, wrong password, operator not accepted), `binding-required`, `bad-signature`, `method-disabled`, `rate-limited`,
  `bad-request`, `seal-failed`, and for a reverse host `busy`, `proof-required`, `proof-failed`. `who` = `{ username?, fingerprint?,
  address? }`; `detail` is human text and not stable. A callback that throws is logged and changes nothing. The existing log
  lines are unchanged. Types in `host.d.ts` (`WshOnRefused`, `WshRefusalReason`). The Rust hosts have no such callback (README matrix).
- **`wsh --version`** (Rust CLI) printed a fixed `0.1.0` for every release; it now prints the workspace version (`wsh 0.11.0`,
  also `-V`), the number of the `rust-vX.Y.Z` tag. `wsh-server --version` already did.
- The bundle grows by about 1 kB gzip in `./host`, `./memory` and `./reverse` (the code table and the callback plumbing);
  `scripts/bundle-budget.json` updated. `.` (the client) is unchanged.
- Tests: `test/host-refused.test.mjs`; `test/rust/wsh-version.test.mjs`; a type fixture in `test/types/memory.ts`.

### Rust: a reverse host no longer loses the last output of a command that exits at once; no process umask swap; two flaky tests fixed (#162)

Rust workspace and tests only (no `src/` change, no wire change); lands in the next `rust-v` release.

- **`wsh reverse` host: output lost before the exit (fix).** A host session's output reader and its exit watcher are independent
  tasks. A child that wrote and exited at once (`sleep 0.05; echo done`), on a loaded machine, could have its exit handled before
  the reader had taken the output out of the pty: `Exit` and `Close` went out, the session was dropped and the output never
  arrived (an operator saw an empty result and a clean exit). The host now waits (at most 1 s, since a grandchild can hold the pty
  open) for the reader to reach EOF and sends what it queued before `Exit`. This was the "sealed-bridge recording hop returns
  empty output" flake of #162; it is not specific to sealing.
- **`wsh -L SOCKET`: the process umask is no longer swapped.** `bind_local_unix` changed the umask around the bind, which races
  any thread creating files (directories came out `0600`). It now binds in a private `0700` staging directory next to the socket,
  sets `0600` there and hard-links it into place (as the server's gateway does). The resulting socket is `0600` as before; an
  existing file is still refused and never replaced except a stale socket with `--replace-socket`. The test-only `UMASK_GATE`
  that worked around the swap is gone.
- **Test: "closes a connection whose client sends past the credit".** Five fixed 60 KiB writes were not always past the credit: on
  Linux the kernel buffers of the two unix sockets absorb them, the server hands credit back as the origin "takes" it, and no
  overrun happens (on macOS the buffers are tiny). The test now keeps sending until the server closes the connection. The server
  enforcement (`on_data`) was read and is correct.
- Tests: `test/rust/wsh-sealed-bridge.test.mjs` (60 short-lived commands in a row, fails under load without the fix);
  `crates/wsh-cli/src/commands/forward.rs` (a thread making directories while another binds sockets).

## 0.40.0 / Rust `rust-v0.11.0`

### Operator-side shared folders: `wsh --share`, and `onShare` on the JS host (#159) (npm change)

A host with no disk of its own (a browser tab) can use directories of the OPERATOR's machine for a session
(`docker run -v $PWD:/app` through `wsh -L sock:endpoint=docker`). New JS API and new wire messages, negotiated, so released peers
are unaffected either way.

- **Wire** (`spec/wsh-v1.yaml`): feature `shares` (a host lists it when it can use shares); `ShareOffer` `0xa8` (the client names its
  shares once, after login), `ShareRequest` `0xa9` (HOST to client: stat, lstat, readdir with attributes in pages, readlink, open,
  create, read, write, close, mkdir, unlink, rmdir, rename, setattr), `ShareReply` `0xaa` (errno-like codes). A host without the
  feature never receives an offer; a client with no `--share` never sends one. Flow control: the offer promises `max_inflight`
  (16) requests and `max_bytes` (256 KiB) per request or reply. A small file arrives with the `open` (no handle, nothing to close).
- **CLI** (`rust-v` release): `wsh --share NAME=/abs/dir[:ro|:rw]`, repeatable, read-only by default, with `-N`, `-L`, `--via` and a
  command; unix only. Served by descriptor (`openat`, `O_NOFOLLOW` on every component), never following a link out of the root, no
  `..`, no special files, hard-linked files not writable, a replaced root answers `ESTALE`, bounded handles, bytes, directory size
  and rate. New dependency `rustix` (MIT OR Apache-2.0 WITH LLVM-exception; already in the lockfile through `tempfile`).
- **JS host** (npm): `onShare(name, fs, who)` on `createMemoryHost`, `createWshServer` and `createReverseHost`; `fs` is an object of
  async file operations (also shaped like an `fs` backend); browser-safe (`src/shares.mjs`). The bundle grows: `./host` +3.9 kB gzip
  (28.5 to 32.4), `./memory` +4.2 kB, `./reverse` +4.2 kB, `.` +0.25 kB (the three message builders); `scripts/bundle-budget.json` updated.
- Not done: change notification, a Rust host that uses shares, sharing over `wsh reverse-connect`, Windows.
- Tests: `test/shares.test.mjs`; `crates/wsh-cli/src/sharefs/tests.rs` (a hostile-path table; each rule broken once and seen to fail),
  `crates/wsh-client/src/share.rs`; `test/rust/wsh-cli-share.test.mjs` (the real `wsh` against a Node host and a page host through a
  pipe relay); `test/browser/rust-cli-share.spec.mjs` (an in-page host reads a file the built CLI shares).

### Rust CLI: the rendezvous id is not printed anywhere; tests for `-N -L` exiting (#156)

Rust workspace, tests and README only (no `src/` change, no wire change). The `-N -L` exit and the redaction of error lines
landed in #158; this finishes the rest of #156.

- `--verbose` logs (`transport URL`), `wsh check`, `copy-id` and the transport's own `WebSocket connected to ...` line show the
  relay's host and the id shortened (`wss://relay/r/AbCd...`), as the error lines do.
- README: the capability matrix's pipe-relay row and the `--via` paragraph say what the Rust client does today (host-key proof,
  channel binding `host`).
- Tests: `test/rust/wsh-cli-156.test.mjs` (host killed or closed mid-session over a relay and a direct socket: the CLI exits
  non-zero within seconds and removes its sockets; stdout and stderr of five commands over four failure paths, with and without
  `--verbose`, grepped for the id).

## 0.39.0 / Rust `rust-v0.10.0`

### Rust: the sealed bridge (#145, step 5)

Rust workspace and tests only (no `src/` change); negotiated by existing feature strings, so released peers keep working.

- **Sealed bridge, both halves signed, byte-compatible with JS.** `wsh_core::e2e_exchange` (the two `KeyExchange` transcripts;
  vectors printed by `src/e2e-exchange.mjs`), `wsh_client::E2eResponder` and `WshClient::initiate_e2e_with` (verify the peer's
  signed half, sign the initiator half), `bridge_seal::SealedBridge` (a frame sealed by JS opens in Rust and the reverse) and
  `seal_gate::SealGate`: every control message that would cross the relay leaves as an `EncryptedFrame` on channel 0, in send order;
  a plain message on a sealed bridge is dropped; nothing that names a command is sent before the key exists.
- **`wsh reverse-connect --sealed`** (new flag): needs operator proof and a peer that states `e2e-sealed`; fails at once with a sentence
  and sends nothing otherwise. Hybrid X25519+ML-KEM-768, negotiated down to X25519 as JS does.
- **Rust host:** `ReverseAccept.features` lists `e2e`, `e2e-sign`, `e2e-sealed` once it has proven the operator.
  **Behaviour change:** `--require-operator-proof` now also REQUIRES the sealed bridge (the JS rule): an operator that proves but does
  not seal is no longer served plain; its plain messages are not heard, and a bridge that has not sealed within 10 s is dropped.
  **A frame that does not open (tampered, replayed, reordered) closes the bridge** (the JS host drops the frame and ignores the rest).
- Not done here: the sealed bridge is for reverse bridges; see the next section for sealing a whole connection.

### Sealed session: a direct or pipe-relayed connection, gateway and endpoint data included (#155, stage b; npm change)

**This changes `src/` (the JS host): please bump the npm version.** Opt-in and negotiated; released peers keep working.

- **JS host:** `createMemoryHost({ sealSession: 'offer' | 'require' })` and `createWshServer({ sealSession })` (needs `hostKey`; offered on a
  connection with no client-opened data streams, i.e. `dataStreams: false`). Features `e2e-session` and `e2e-session-required` in
  `ServerHello`. After login a `KeyExchange` for the connection's `session_id`, signed by the login key and answered with the host key's
  signature, seals every message but the keepalive (`GatewayData` and `GatewayCredit` included) as `EncryptedFrame`s on channel 0; a plain
  message is dropped, a frame that does not open closes the session; `'require'` refuses a plain client (and a password login).
  `SealedBridge` takes `scope: 'session'`; `E2EResponder`'s `signKey` may be a signer (`{ sign }`).
- **Rust CLI:** `--sealed` seals the session (any command that dials one host), automatic against `e2e-session-required`; against a host that
  does not offer it the CLI fails with a sentence and sends nothing (no silent downgrade). `WshClient::seal_session`, `ConnectConfig.seal_session`.
- **Bundle size** (gzip, `npm run size`): `./host` +0.9 kB, `./memory` +0.7 kB, `./reverse` +0.5 kB, `.` unchanged; `scripts/bundle-budget.json` left as is (within its 10% margin). Browser acceptance: `test/browser/rust-cli-sealed.spec.mjs` (the built `wsh --sealed -N -L` against an in-page host that requires sealing, through a recording pipe).
- **Not done:** the JS client and the Rust server (#155 stage c); a sealed session is not offered with client-opened QMux data streams.
- **#156:** `wsh -N -L ...` now exits (non-zero, "the connection to the host was lost", sockets removed) when the host drops the connection
  (the WebSocket transport never told the dispatch loop the socket had closed); a pipe relay's rendezvous id is shortened in error lines.

## 0.38.1

### JS: `operator-proof` is offered only to a peer that advertises it (npm change)

The JS relay and operator sent `ReverseConnect.features: ['operator-proof']` unconditionally. Released Rust hosts
(`rust-v0.6` to `v0.8`) deny unknown fields, so an operator offering proof to one got a silent timeout.

- A peer that can answer a challenge lists `operator-proof` in its registered capabilities (`connectReverse`, so
  `createReverseHost` too; `operatorProof: false` leaves it out). **This is a registration change visible in `listPeers()`.**
- `reverseConnect(fp, timeout, { proof })`: `'auto'` (default) offers only to a peer whose record lists it (one `listPeers()`
  lookup, or pass `peerCapabilities`); `true` offers regardless; `false` never. `requirePeerProof` / `sealed` against a peer
  that does not advertise it throw at once ("does not advertise "operator-proof" ... nothing was sent").
- The relay forwards `features` only to a peer that registered `operator-proof`, and strips it otherwise (no new wire field).
- **Behaviour change:** a JS host from npm 0.36-0.38 registers no such capability, so a new operator no longer offers proof
  to it under `'auto'` and a `requireOperatorProof` host refuses it ("operator proof required") until it is upgraded;
  `proof: true` does not help through this relay, which strips for it. Upgrade the host.
- Spec text for `ListenUnix` now says what both hosts send: `InboundOpen` `peer_addr "unix"`, `peer_port 0`.

### Test: `npm run test:rust` can no longer hang a CI job (#152)

No product change; neither the npm package nor the Rust binaries change.

- **The hang was a test artefact, not a protocol defect.** In the large-transfer test of `wsh -L ...:endpoint=NAME` the fake daemon was Node's `http` server on a `Duplex.fromWeb` socket. Under CPU load (about 1 run in 80) that server stopped: `res.writableNeedDrain` stayed true on a socket that had nothing buffered, so `req.pipe(res)` waited for a `drain` that never came, the host stopped consuming, never returned `GatewayCredit`, and `wsh` correctly waited for credit. `wsh` was idle, credit windows and the QMux windows were consistent, and the same http fixture between two JS peers or on the raw transport passed hundreds of runs; with raw web-stream endpoints the Rust client passed 900 of 900 runs under the same load. rust-v0.8.0/0.9.0 and npm 0.37/0.38 are not affected. The test now uses raw `bulk` and `echo` endpoints.
- Every file under `test/rust/` imports `test/rust/helpers/guard.mjs`: its child processes are tracked and killed when the file ends, on exit or on a signal, and `npm run test:rust` passes `--test-timeout=180000`, so a hung test fails in seconds naming itself.
- The CI `browser` and `rust` jobs have `timeout-minutes` (25 and 40).

## Rust `rust-v0.9.0`

### Rust: host identity, channel binding and operator proof (#145, part 3: steps 1-4)

Rust workspace plus one relay-side fix; the npm package is unchanged. Everything new is negotiated by the existing feature
strings (`host-key-nonce:`, `host-key:`, `host-key-sig:`, `channel-binding:host`, `channel-binding-required`,
`operator-proof`), so released peers (npm 0.36-0.38, rust-v0.6-0.8) keep working.

- **Breaking (CLI): a first use of a host key now needs a yes.** The Rust CLI used to record any key a host presented, on
  first use, silently. It now records only a key the host PROVED it holds (it sends `host-key-nonce:`, checks
  `host-key`/`host-key-sig` before any credential), and a first use is refused unless you answer yes at a terminal or pass
  `--accept-new-host-key` (scripts, `wsh agent`). A CHANGED key is always refused. **To get the old behaviour back for a
  script, add `--accept-new-host-key`.** A host that presents no proof (every `wsh-server` before this, and any host with no
  key) is still connected to, nothing is recorded for it, and `--require-host-key` refuses it. The `fingerprints[0]` guess
  is no longer recorded; an entry an old client recorded that way keeps working only while the host still sends no
  `host_fingerprint`, and a host that has a pinned key but proves none now is refused as a downgrade.
- `--require-channel-binding`; the client binds its login to the proven host key (kind `host`) whenever the host offers it and
  honours `channel-binding-required`. `cert-hash` and `tls-exporter` are not in Rust.
- `wsh-server`: `[server] host_key = "<path>"` (PKCS#8 PEM like the Node host; created 0600 on first start; a key other users
  can read is refused) gives it `ServerHello.host_fingerprint` and the proof; `require_channel_binding = true` (needs
  `host_key`) refuses an unbound login. **Off by default**: turning `host_key` on makes a released Rust client that pinned
  `fingerprints[0]` report the host key as changed.
- Operator proof in reverse mode: the Rust relay lists `operator-proof` and carries `ReverseChallenge`, `ReverseProof` and
  `ReverseConnect.features`; **the relay now stamps the operator's authenticated login name into the forwarded
  `ReverseConnect.username`** (it forwarded what the client wrote). `wsh reverse-connect` answers the host's challenge
  (`--operator-proof`, `--no-operator-proof`; by default only when the peer registered the `operator-proof` capability, since a
  released Rust host cannot decode `ReverseConnect.features`); `wsh reverse` and `wsh agent run` issue the challenge, verify the
  proof before accepting, and take `--require-operator-proof` and `--allow-operator <fingerprint>`. A reattach by the same
  operator now also needs the same `from_fingerprint`. **Not done: the sealed bridge (`e2e-sealed`) and signed `KeyExchange`
  halves**, so proof says who connected, not that later plain messages came from them.

## Rust `rust-v0.8.0`

### Rust: identity parity, part 1 (#145)

Rust workspace only (`wsh`, `wsh-server`, `wsh-client`); no message or field was added to the wire, and the npm package is
unchanged. **The Rust `wsh-server` changes one default (`client_env`) and one value it sends (`AuthOk.ttl`). Read both.**

- **Breaking: the Rust `wsh-server` applies only an allow-list of the environment a client sends (#126).** Before, every
  variable in `Open.env` reached the command, so a client could set `PATH`, `LD_PRELOAD`, `BASH_ENV` or `LD_LIBRARY_PATH`
  for what the server runs. Now: `TERM`, `COLORTERM`, `LANG`, `LANGUAGE` and `LC_*` (the JS host's default), at most 64
  variables with bounded names and values. **To get the old behaviour back, put this in `config.toml`:**

  ```toml
  [server]
  client_env = true    # every variable the client sends; the server logs a warning at start-up
  ```

  `client_env = false` accepts nothing; a list (`client_env = ["TERM", "LC_*", "EDITOR"]`, a trailing `*` makes a prefix)
  accepts exactly those names and replaces the default list. A deployment that relied on a client passing its own
  variables (a `JAVA_HOME`, a `GIT_*`, an `AWS_*`) to a command needs a list or `true`. Fix with it: the pty no longer
  overwrites the client's `TERM` with `xterm-256color` (it is the default only when the client sent none).
- **Behaviour change: `AuthOk.ttl` is 0 from the Rust `wsh-server` (#125).** It sent `session_ttl` (86400 by default), a
  lifetime nothing enforced; `session_ttl` is the lifetime of a detached session. Now `ttl: 0`, which the spec reads as
  "no limit promised". `AuthOk.token` is still an HMAC (released clients require a non-empty field) but is documented as
  opaque: no message accepts it back, so do not use it as a credential. A client that read `ttl` as a connection lifetime
  (the JS client's `authTtl`) now sees 0 from a Rust host.
- **Fix: the Rust `wsh-server` honours `Signal` (#145).** It only logged it, so the `SIGINT` that `wsh host command` forwards
  did not stop the command. It now delivers `HUP INT QUIT TERM KILL USR1 USR2 WINCH CONT STOP TSTP ALRM` (with or without
  `SIG`, any case) to a pty session's foreground process group (what ^C reaches) and, for an exec on pipes (which now
  runs in its own process group so a shell that did not exec its last command cannot swallow the signal), to that group.
  Another name is ignored; only the control attachment of the connection that owns the channel can send one, not a viewer.
- **Fix: `wsh-server --generate-cert` makes a leaf certificate (#145).** It was flagged as a CA, which TLS clients refuse
  as a server certificate, so the only way to connect was `WSH_INSECURE_LOOPBACK_TLS=1` (verification off). It is now a
  self-signed leaf: `SSL_CERT_FILE=~/.wsh/cert.pem wsh -t ws ...` verifies it. An existing `~/.wsh/cert.pem` is not
  regenerated; delete it to get the new one.
- **New: `wsh --via wss://relay/r/<id> user@host [command...]` dials the operator side of a pipe relay (#118, #145).**
  `user@host` stays the identity and its key is recorded in `~/.wsh/known_hosts` under `host:port` (what a direct
  connection uses), not under the relay's address; a different host behind that name is refused with `HOST KEY CHANGED`
  before a command is sent, whichever relay carried it. A URL target (`wsh alice@wss://relay/r/<id> ...`) also dials but is
  pinned under the relay's authority, so prefer `--via`. `--via` works with `wsh [user@]host`, `connect`, `scp`, `ls`,
  `sftp` and `copy-id`; it refuses the `?role=host` URL, a URL without `/r/<id>`, `https://`, and a URL target; the
  rendezvous id is not saved to `last_session.json`. `wsh-client`'s `ConnectConfig` gains `known_host: Option<String>`
  (default `None`: the URL's authority, as before). **Not done here:** the Rust client still does not verify the host-key
  proof, bind the login to the host key, answer an operator challenge or seal the bridge (next part of #145); see the
  README's Security model for what that leaves open over a pipe relay.
- **Tests:** `test/rust/wsh-cli-pipe.test.mjs` runs the built `wsh` through the real `createPipeRelay` to a Node host
  (`createWshServer().accept`) and to a page-shaped host (`createMemoryHost().accept`, `dataStreams: false`): a command
  runs, the key lands under `user@host`, an impostor key and a page host with another key are refused with nothing run,
  the pin follows the name across relays, an unauthorized operator is refused by the host, malformed `--via` values.
  `test/rust/wsh-rust-server-defaults.test.mjs` gains the `client_env` cases (default, `true`, a list, `false`; pty and
  pipes), `ttl` 0, and `Signal` ending a running command on a pty and on pipes while an unknown name is ignored; unit tests
  cover the allow-list, the config line above, signal names and `--via` parsing. `test/rust/wsh-cli.test.mjs` trusts the
  generated certificate through `SSL_CERT_FILE` instead of `WSH_INSECURE_LOOPBACK_TLS`.

### Rust: forwarding (#145)

Rust workspace only (`wsh`, `wsh-server`, `wsh-client`, `wsh-core`); no message or field was added to the wire. **Read the
two behaviour changes marked below.**

- **`GatewayCredit` / `gateway-credit` in `wsh-server` and `wsh-client`.** 256 KiB initial credit per direction, returned as
  data is consumed; a peer that exceeds its credit is closed. The server advertises it with the gateway, the client lists it
  in `Hello.features`; both needed. Without it the server closes a connection holding more than `[gateway]
  max_buffered_bytes` (default 4 MiB) of unconsumed client data, or a client holding more than `max_client_buffered_bytes`
  (32 MiB): the Node host's numbers. `OpenUdp` flows are metered too.
- **New: `OpenUnix` / `ListenUnix` in `wsh-server`, off by default**, with the Node host's policy: `[gateway] unix_connect`,
  `unix_listen` (exact path, `/dir/` prefix, `@abstract` on Linux), `unix_replace_stale`, `unix_max_listeners`. Paths are
  checked after `realpath` of the parent, the target must be a socket, no symlink escape, created sockets are `0600` and
  unlinked on close, a stale socket is replaced only if asked AND allowed, a bad pattern stops start-up. `gateway-unix` is
  advertised only when a socket is listed.
- **Behaviour change: gateway tables are per client connection.** `gateway_id`/`listener_id` used to be one table for the
  whole server (a client could address, and close, another client's connection). `GatewayClose` is now a half-close, as on
  the Node host (the origin gets 1 s to finish), where it used to tear the connection down at once. Opens no longer block
  the session loop. Over the connection limit the answer is code 7 (was 4); the new `[gateway]` keys are above.
- **Behaviour change: reverse listeners and inbound connections are bounded** (16 unanswered per client, 30 s to answer).
- **New in `wsh-client`:** `open_tcp`, `open_unix`, `open_endpoint`, `listen_unix`, `listen_tcp`, `WshClient::gateway()`,
  `GatewayStream` (`read`, `write_all`, `shutdown`, `pump`), `GatewayListener`. `Hello.features` now lists `gateway-credit`.
- **New: `wsh -L`, `-R`, `-N`, `--replace-socket`**, with TCP, unix and named-endpoint (`endpoint=NAME`) ends; see the README.
  Works with `--via`. Local sockets `0600`, removed on exit, an existing file refused unless `--replace-socket`.
- **Tests:** Rust unit tests (session, policy, client hub, spec parsing); `test/rust/wsh-rust-server-forwarding.test.mjs`
  (the JS client against the real `wsh-server`: the Node host's unix and credit cases, flat memory with a stalled client);
  `test/rust/wsh-cli-forward.test.mjs` (the built `wsh` against a Node host and an in-page `createMemoryHost({ endpoints })`
  host, through `createPipeRelay` with `--via` and over a plain byte pipe, and against `wsh-server`: fake HTTP daemon, 20 MiB
  both ways, stalled reader, refusals). Browser suite: an in-page host's endpoint reached by the freshly built `wsh -L`
  (`WSH_CLI_BIN`); the 50 ms pause for #135 is removed.

## 0.38.0

### npm package: TCP reverse tunnels and UDP over WebTransport datagrams (#98, #124)
- **TCP reverse tunnels on the Node host (#98).** `ListenRequest { listener_id, port, bind_addr }` was answered with a
  `ListenFail`; it is now served when `createWshServer({ gateway: { reverse: {...} } })` is set. **Off by default** (a
  separate switch from outbound gateway use). The host announces each inbound connection with `InboundOpen` (the real
  `peer_addr` / `peer_port`), the client answers `InboundAccept { gateway_id }` or `InboundReject`, and data flows with the
  same `GatewayCredit` rules as any gateway connection. Policy: the host binds `reverse.bindAddr` (default `127.0.0.1`) and
  **ignores the client's `bind_addr`** (its wire default is `"0.0.0.0"`) unless it is listed in `reverse.allowBindAddrs`,
  as the Rust server does with `reverse_bind_addr`; `reverse.ports` (default `[0, "1024-65535"]`, a given list replaces it,
  nothing below 1024 unless named); `maxListeners` 4 per client, `maxConnectionsPerListener` 16, `backlog` 8, `idleMs`
  300000; listeners close with the client. Each refusal says why in `ListenFail.reason`. Reverse connections count against
  `maxConnections`. A host with only `reverse` (`allow: []`) advertises `gateway`. Client: `client.listenTcp(port,
  { bindAddr?, onConnection(duplex, { peer, peerPort }) })` resolving `{ port, close() }` (like `listenUnix`).
- **UDP as WebTransport datagrams (#124), feature `gateway-datagram`.** When the transport is WebTransport and both ends
  list `gateway-datagram` (client in `Hello.features` if its transport has datagrams; host in `ServerHello.features` if it
  is on WebTransport, serves UDP and `udp.datagrams` is not false), `OpenUdp` payloads travel as WebTransport datagrams:
  the datagram is the 4-byte big-endian `gateway_id` and then the UDP payload. No retransmission, no head-of-line blocking
  against other flows, not metered by `GatewayCredit`; `OpenUdp`/`GatewayOk`/`GatewayFail`/`GatewayClose` stay on the
  control stream. WebSocket, an older peer, or `udp.datagrams: false` keep the reliable path unchanged. The limit comes
  from the transport's `maxDatagramSize` (about 1207 payload bytes on QUIC), read per payload; a larger payload goes on the
  control stream by default (`udp.oversize: 'reliable'`; the choice and why are in the README), or is dropped and counted
  with `udp.oversize: 'drop'` / `openUdp(h, p, { oversize: 'drop' })` (`send()` then rejects with `RangeError`).
  `client.openUdp()` now returns a `UdpFlow` (still `readable` / `writable` / `close` / `destroy` / `closed`) with
  `send(bytes) => Promise<boolean>`, `transport`, `maxDatagramSize`, `stats`, and explicit drop semantics (a slow reader
  loses the newest past 128 queued datagrams). `WshTransport` gained `supportsDatagrams`, `maxDatagramSize`,
  `sendDatagram()` and `onDatagram`; `createWshServer` gained `gatewayStats()`.
  - **Bounds** (`gateway.udp`): `maxFlows` 16 per client, `packetsPerSecondPerFlow` 500, `packetsPerSecondPerClient` 2000,
    `bytesPerSecondPerClient` 4 MiB/s (both directions; the amplification bound), `udpIdleMs` 60 s. Over a limit a datagram
    is dropped and counted. These apply to the reliable path as well, **which is a behaviour change for UDP flows on the
    reliable path** (previously only the flow cap `maxConnections` and the receive queue applied).
  - **One destination, never a relay:** the same name rule and resolved-address policy as TCP; the host's socket is
    `connect()`ed to the checked address, so replies are accepted only from that address and port.
  - **Wire additions:** feature string `gateway-datagram` (both directions of negotiation); the datagram layout above. No
    new control message and no new field. Documented in `spec/wsh-v1.yaml` (descriptions of `OpenUdp` and `ListenRequest`).
  - **Rust must still implement** (see the README capability matrix): `gateway-datagram` on WebTransport, the datagram
    layout, `maxDatagramSize` handling, and the rate / flow bounds; for reverse tunnels a port allow-list and per-client
    listener, per-listener connection and idle bounds.
  - **Tests:** `test/gateway-reverse.test.mjs`, `test/gateway-datagram.test.mjs` (a real HTTP/3 connection from the Node
    WebTransport client to the host: DNS-sized and limit-sized datagrams, a 1252-byte payload, loss shims on both
    directions, oversize, rate / flow / idle bounds, policy, a third party's datagram not delivered, WebSocket fallback),
    and `test/browser/udp-datagrams.spec.mjs` (Chromium over HTTP/3 with `serverCertificateHashes`). Every new rule was
    broken once to see its test fail.
  - **Bundle size:** `.` +5.0 kB minified / +1.4 kB gzip (client reverse and UDP API, datagram flow, transport hooks);
    `./host` +0.2 kB / +0.1 kB gzip; budgets in `scripts/bundle-budget.json` updated by exactly that.

## 0.37.0 / Rust `rust-v0.7.0`

### npm package: gateway forwarding (#120, #123, #98, #124)
- **Security fix and behaviour change: the Node gateway checks the resolved address.** The `gateway` option of
  `createWshServer` matched `allow` against the NAME a client sent and dialled that name; it now checks the address the
  name resolves to as well. The host resolves the name once, drops every address that
  is not globally routable, and connects to the address it checked (never the name again). "Not globally routable" covers
  IPv4 loopback, private, link-local, CGNAT, documentation, benchmarking, multicast and reserved ranges, IPv6 loopback,
  unspecified, ULA, link-local, site-local, multicast, documentation and deprecated ranges, and IPv4 wrapped in IPv6
  (IPv4-mapped, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`). `ResolveDns` answers are filtered with the same rule, so the host
  does not hand out internal addresses and a later `OpenTcp` to one is refused. `GatewayOk.resolved_addr` now carries the
  address that was connected to.
  - **Breaking for existing deployments:** a gateway that reached loopback or private space (`allow: ['*']` to a local
    service, `allow: ['broker.lan:1883']` for a LAN broker, `localhost`) is now refused with `POLICY_DENIED` until you say
    so explicitly: `gateway.allowPrivate: ['10.0.0.0/8', '127.0.0.1', ...]` (CIDR blocks or addresses), or an `allow`
    entry that is itself an IP literal (`"192.168.1.5:1883"`, which permits exactly that address). Public destinations are
    unaffected. Through `socks` the name still goes to the proxy unresolved (nothing to check); IP literals are checked.
  - The Rust `wsh-server` closed the same gap separately (see "Breaking: Rust `wsh-server` defaults" below): a server
    built before that change still matches only the name.
  - **Tests:** `test/gateway-address-guard.test.mjs` (the guard over IPv4, IPv6, mapped, NAT64, 6to4, malformed input),
    `test/gateway-address-policy.test.mjs` (an allowed name resolving to loopback/private/link-local/mapped/NAT64 refused
    after exactly one lookup; connect uses the checked address; literals and the odd numeric spellings; `allowPrivate`
    and literal rules; ResolveDns filtering; SOCKS literals).
- **Gateway flow control (#123), feature `gateway-credit`.** Gateway data was forwarded without regard to a slow reader
  (`sock.on('data')` never paused, `write()`'s result ignored), so a slow peer on either side made the host buffer without
  bound. Now each direction of each gateway connection is metered: `GatewayCredit { gateway_id, bytes }` (0x7f), 256 KiB
  of initial credit per direction, returned as the receiver's application consumes data (for the host: when the origin
  socket has taken it; for a client: when the stream is read). The origin socket is paused while a chunk waits for credit
  or for the transport, and a peer that sends beyond its credit is closed. The client lists `gateway-credit` in
  `Hello.features` and the host in `ServerHello.features`; credit is used only when both did. Against a peer without it
  (every released client and host) the host holds the origin back by the transport's own write backpressure and bounds
  what a client can make it hold: `gateway.maxBufferedBytes` (default 4 MiB per connection) and
  `gateway.maxClientBufferedBytes` (default 32 MiB per client); a connection that exceeds one is closed with
  `GatewayClose { reason: "buffer limit exceeded" }`. **Behaviour change:** an older client that bursts more than those
  caps at an origin that does not read is now cut off instead of buffered without limit.
  `GatewayClose` is now documented and implemented as a half-close (the closer sends no more, keeps receiving until the
  peer's own `GatewayClose`), which is what the host already did with its 1 s grace.
  - **Tests:** `test/gateway-flow-control.test.mjs` (credit unit tests; a fast origin with a stalled client: the origin
    makes no progress and memory stays flat; a stalled origin with a fast client; an older peer, held back and capped;
    overrun closed; a 24 MiB transfer completes).
- **Unix-domain socket forwarding (#120), both directions, modelled on OpenSSH streamlocal. JS only for now.** New
  messages: `OpenUnix { gateway_id, path }` (0x63), `ListenUnix { listener_id, path, replace? }` (0x65) and
  `OpenEndpoint { gateway_id, name }` (0x64), behind host features `gateway-unix` and `gateway-endpoints`; they reuse
  `GatewayOk/Fail/Close/Data/Credit` and, for listening, `ListenOk` (`actual_port: 0`) / `ListenFail` / `ListenClose` /
  `InboundOpen` / `InboundAccept{gateway_id}`. An old peer ignores what it does not know and never sees them: a client sends
  them only to a host that advertised the feature.
  - Host policy (off by default): `gateway.unix: { connect: [...], listen: [...], replaceStale, maxListeners }`; exact paths,
    `"/dir/"` prefixes, `"@abstract"` names (refused unless listed); checked after `realpath` of the parent, `..` refused,
    the file must be a socket and not a symlink. Sockets the host creates are `0600` and unlinked on close or disconnect;
    an existing socket is replaced only when the request says `replace` AND `replaceStale` is true AND it is stale (nothing
    accepts on it); a non-socket file is never touched (the `StreamLocalBindUnlink` question: default no).
  - Client: `client.openUnix(path)`, `openEndpoint(name)`, `openTcp(host, port)` (the TCP egress, same streams),
    `listenUnix(path, { onConnection })`, each a web-streams duplex with backpressure; and under Node
    `client.forwardUnix({ local, remote, reverse })` for the `ssh -L` / `-R` shapes with `host:port` and socket-path ends mixed
    (`-L 127.0.0.1:2375:/var/run/docker.sock`).
  - **Named virtual endpoints:** `createMemoryHost({ endpoints: { name: (duplex, who) => ... } })` (and `gateway.endpoints`
    on the Node host) for a host with no file system; `who` is `{ username, fingerprint }`, and `{ open, authorize(who) }`
    authorises per call. They are a separate message, not a reserved path, so a name cannot be confused with a file path and
    the file-system policy is not involved. On the memory host the gateway offers endpoints only (no TCP, DNS or sockets).
  - **Not done:** the Rust `wsh-server` and `wsh` CLI (`-L`/`-R` with sockets): the exact work is in the README
    ([Gateway](README.md#unix-domain-sockets-streamlocal-and-named-endpoints)). UDP (#98, #124) is not in this change.
  - **Tests:** `test/gateway-unix.test.mjs` (a fake Docker-style HTTP daemon on a real unix socket through `openUnix` and
    `forwardUnix` in every TCP/unix mix, 20 MiB both ways, 24 concurrent connections, the connection cap, every policy
    refusal including symlink escapes, `0600`, unlink on close and on disconnect, the stale-socket rules),
    `test/gateway-endpoints.test.mjs` (memory host: who, allow-list, per-call authorisation, backpressure, disconnect).
- **`OpenUdp` on the Node host (#98, first half of #124), over the existing reliable path.** `OpenUdp` used to be refused
  with a `GatewayFail`; the gateway now serves it with the TCP destination policy (name rule, then the resolved address
  checked and connected to as checked; not through `socks`). One `GatewayData` is one datagram (at most 65507 bytes); a
  datagram the client cannot take fast enough is dropped by the host instead of buffered; idle flows close after
  `gateway.udpIdleMs` (default 60000); flows count against `maxConnections`. Client: `client.openUdp(host, port)`.
  No new messages or features. Because it rides the ordered, reliable control stream it has head-of-line blocking and
  retransmission: **WebTransport datagrams, per-flow datagram ids, MTU handling and per-client rate bounds (the rest of
  #124) are not implemented.** The Rust `wsh-server` already answers `OpenUdp`. Tests: `test/gateway-udp.test.mjs`.
- The message count is 105 with the identity messages (`GatewayCredit`, `OpenUnix`, `OpenEndpoint`, `ListenUnix`); `spec/wsh-v1.yaml` and the three
  generated outputs are updated.
- **Named endpoints work in a page, and the gateway is split in two.** `createMemoryHost({ endpoints })` is built from
  `src/server/gateway-core.mjs` (the connection table, credit accounting, per-client budget, `OpenEndpoint`, the feature
  list), which imports no Node built-in; `src/server/gateway.mjs` (TCP, DNS, UDP, unix sockets) builds on it and is still
  only reachable from `@johnhenry/wsh/server`. `connection.mjs` still does not import `gateway.mjs`: it calls
  `cfg.createGatewaySession(cfg.gateway, send, log, { who })`, which `createWshServer` passes next to `gateway` and
  `createMemoryHost` passes as the endpoints-only session (it answers TCP, DNS, UDP, unix and listen requests with a
  `GatewayFail` / `ListenFail` instead of silence). The gateway-credit exchange therefore works over a byte pipe to an
  in-page host. Browser bundle budget (gzip) grew by the gateway core, the gateway channel and the client's gateway
  methods: see `scripts/bundle-budget.json`. Test: `test/browser/endpoint.spec.mjs` (Playwright).

### npm package: identity (#117, #118, #119, #125, #126)

Identity: who is on the other end, and what a relay can do about it. Everything wire-visible is optional and negotiated
by feature strings, so released clients (npm 0.35.0, Rust `rust-v0.6.0`) and hosts keep working; the one default that
changes is `clientEnv` below, and it is breaking.

- **BREAKING default: `clientEnv` is an allow-list (#126).** A client's `openSession({ env })` used to be applied
  whole to the command or shell the host ran, so a client could set `PATH`, `LD_PRELOAD` or `BASH_ENV` and defeat a host
  that restricts what runs (`exec` as a function, a fixed command set). The default is now `TERM`, `COLORTERM`, `LANG`,
  `LANGUAGE` and `LC_*` (sshd's `AcceptEnv` shape), for `exec` and, new, for `pty`. `exec: { clientEnv: true }` restores
  the old behaviour; `false` accepts nothing; an array of names or `PREFIX_*` patterns (replacing the default list) or a
  predicate `(name, value) => boolean` takes anything in between. Names must be plain identifiers; at most 64 variables
  of at most 4096 bytes are considered. Hosts that passed `clientEnv: false` are unchanged. The Rust `wsh-server` still
  applies whatever environment the client sends.
- **Default change: `AuthOk.ttl` is now `0` ("no limit promised"), not `3600` (#125).** Nothing ever enforced the 3600, so
  no connection behaves differently, but a client that read `ttl` as "this login expires in an hour" now sees `0`; set
  `connectionTtlMs` to have the host really enforce and advertise a lifetime.
- **`AuthOk.ttl` is true, `AuthOk.token` is honest (#125).** The fields stay on the wire (released peers require them, so
  removing them would break the Rust client), but they no longer promise what nothing delivered. `ttl` is the lifetime the
  host enforces: `createWshServer({ connectionTtlMs })` ends every authenticated connection that long after login and
  advertises it in whole seconds (rounded up; `client.authTtl`); without it the host sends `ttl: 0` ("no limit
  promised") instead of an unenforced 3600. `token` is documented as an opaque per-connection value with no authority
  -- nothing accepts it back; `Resume` and `Attach` use the per-session token from `OpenOk`. The spec text no longer
  says "a signed session token". The Rust `wsh-server` still sends an unenforced `session_ttl` and an HMAC no one checks.
- **Channel binding (#119).** The auth transcript's `channel_binding` slot, empty since 0.1, is populated with what
  each transport offers: the `host` key the client saw prove possession (a relay presenting its own key binds to its
  own), the pinned WebTransport `cert-hash`, and a `tls-exporter` (Node on both ends, over `wss://` the process serves
  itself; browsers and Node's global `WebSocket` cannot compute it). Negotiated with `channel-binding:<kind>` and
  `channel-binding-required` features in `ServerHello` -- no new field, empty binding when nothing is offered, so the
  transcript released peers sign is unchanged. `createWshServer({ requireChannelBinding: true | [kinds] })` refuses an
  unbound login with a reason; `connect(url, { requireChannelBinding })` refuses to sign one (it also defeats an
  intermediary that strips the host's offer). `client.channelBinding` says what a login covered. Spec text and two test
  vectors under `Auth`. Does not protect a login nobody requires binding for, password logins, or anything through a
  TLS-terminating proxy (for `tls-exporter`); the Rust server and client neither offer nor compute one.
- **Operator proof to the peer, and sealed bridges (#117; see #93).** In reverse mode the host's `accept` trusted the
  relay's `from_fingerprint`. New optional messages `ReverseChallenge` (0x58) and `ReverseProof` (0x59) and
  `ReverseConnect.features`: the host sends a challenge signed with its own key (so the operator knows whom it is
  proving itself to, and that the host saw the operator's own fingerprint -- a rewritten `from_fingerprint` shows up);
  the operator signs the host's key, its own key, its username and the host's single-use nonce and session id; the host
  verifies it **before `accept`**, and `accept` now receives `{ fingerprint, username, proven, publicKey }`. A relay lists
  `operator-proof` in its `ServerHello` and carries the two messages (the JS relay does; the Rust relay does not, so the
  operator does not offer there). `createReverseHost({ requireOperatorProof: true })` makes it mandatory *and* seals the
  bridge: `KeyExchange.signature` is now also signed by the **initiator** (a different label, so it cannot pass for the
  responder's), the host verifies it against the proven operator key, and the `KeyExchange` for the bridge (session id =
  the challenge's) keys a channel on which every message that would cross the relay travels as an `EncryptedFrame` with
  `channel_id` 0 and a strict counter; the host drops plaintext. `client.reverseConnect(fp, timeout, { proof, sealed,
  requirePeerProof })`; nothing that names a command, a path or a session is sent before the key exists. Before this
  `Open` (command, environment) and `OpenOk` (resume token) crossed the relay in the clear until a per-session
  `initiateE2E`. By default a host still serves operators that do not prove themselves, and a new operator/host pair
  now exchanges the challenge automatically and the host states `e2e-sealed` in `ReverseAccept.features` (a visible
  extra string). README: [Operator proof and sealed bridges](README.md#operator-proof-and-sealed-bridges-117) has the
  table of what a relay can and cannot do, with and without it. Not in the Rust `wsh-server` / `wsh` (regenerated
  types only; `ReverseConnect.features` is `None` there).
- **Pipe relay (#118).** `@johnhenry/wsh/pipe-relay`: `createPipeRelay()` pairs one host connection and one operator
  connection by an unguessable rendezvous id (`newRendezvousId()`, `pipeUrl()`) and copies WebSocket messages both ways with
  backpressure, bounded in waiting halves, rendezvous time, idle time, lifetime, bytes, message size and early bytes. It
  parses nothing of wsh, so the host authenticates the operator itself, exactly as on a direct connection, and the
  operator can pin the host key. The module has no imports (`ws`, `node:http` and `node:https` are loaded lazily by
  `listen()`), and a test walks its module graph to keep it so. The Rust `wsh` CLI always dials `wss://<host>/` (#136), so it
  cannot use it until it grows `--via` or keeps the URL path.
- **In a page (the browser-safe entry points).** `@johnhenry/wsh/reverse`'s `createReverseHost` takes `requireOperatorProof`,
  `proofTimeoutMs` and the proof-aware `accept({ fingerprint, username, proven, publicKey })`, with the sealed bridge:
  all WebCrypto, no Node built-in and no `Buffer` (the bundle test checks it). `createMemoryHost` gained
  `connectionTtlMs` and `requireChannelBinding` (`true` or `['host']`, needs `hostKey`: the host key is the one thing a
  memory host can bind a login to, so `accept(socket)` hosts with a `hostKey` bind kind `host`); `clientEnv` is typed
  as `boolean | string[] | predicate` in `memory-host.d.ts`, `host.d.ts` and `reverse-host.d.ts`. `@johnhenry/wsh/pipe-relay`
  is a relay and stays Node-only (it listens through `ws` and `node:http`); a page is the host or operator behind it, and
  the bundle test names it as the one deliberate exception. Browser bundle sizes grew by what this adds (see
  `scripts/bundle-budget.json`).
- **Fix: a sealed bridge stalled about half the time with a host in Chromium.** `initiateE2E` registered the waiter for
  the responder's ML-KEM ciphertext after awaiting the responder's signature check; the ciphertext follows the reply at
  once and was dropped in that window ("Timed out waiting for peer ML-KEM-768 ciphertext"). It is now registered
  before the check.
- **Not done:** #122 (per-key capabilities shared by both hosts) is left for a later change; the design is in the PR
  description. The Rust side of #117, #119 and #125.
- **Tests:** `test/client-env.test.mjs`, `test/auth-ok-ttl.test.mjs`, `test/channel-binding.test.mjs` (vectors; a
  relaying and a TLS-terminating intermediary against hosts that do and do not require binding; WebTransport `cert-hash`),
  `test/pipe-relay.test.mjs` (module graph, rendezvous, every bound, backpressure, then the same authentication
  checks directly and through the pipe, including pinning and an impostor host), `test/operator-proof.test.mjs` (a hostile relay
  that rewrites `from_fingerprint`, replays a proof, swaps the operator's key and injects an `Open` against a host that
  requires proof; what the relay can and cannot read of a sealed bridge). The existing relay-bridge test now also sees
  `e2e-sealed` among a proven host's bridged features. `test/memory-host-identity.test.mjs` (channel binding `host`,
  `connectionTtlMs`, `clientEnv` on the memory host) and `test/browser/identity.spec.mjs` (Chromium: an in-page host
  behind the pipe relay -- pinning, binding, an unknown key, the env allow-list; an in-page reverse host that requires
  operator proof behind the hostile relay -- sealed bridge, no proof refused, a rewritten `from_fingerprint`, an injected `Open`).

### Rust workspace changes in the same release

Rust workspace only (`wsh`, `wsh-server`, `wsh-client`); the npm package and the wire protocol are unchanged, and no
message or field was added. **The Rust `wsh-server` changes three defaults. Read "Breaking" before upgrading it.**

### Breaking: Rust `wsh-server` defaults

- **The gateway is off, and allows no destination when on.** Before: `[gateway] enabled = true`,
  `allowed_destinations = ["*"]`, so any authorized key could open TCP/UDP connections and DNS lookups from the host,
  including to loopback, private and link-local addresses. Now: `enabled = false` (and `gateway` is not advertised),
  `allowed_destinations = []`, and even with `"*"` an address that is loopback, link-local, private, unique-local,
  carrier-grade NAT, unspecified or multicast is refused after resolution unless a rule names that host, address or
  range (`"db.internal:5432"`, `"10.1.0.0/16:5432"`, `"127.0.0.1:8080"`). The server connects to the address it checked
  instead of resolving the name again, and `ResolveDns` no longer returns internal answers. Rules are now also parsed
  for address ranges (`10.0.0.0/8`, `10.0.0.0/8:443`, `fd00::/8`), which the old doc example showed but the code never
  matched.
- **Reverse listeners are off and bind to loopback.** Before: `enable_reverse_tunnels = true`, and a listener bound the
  `bind_addr` the client sent (whose wire default is `0.0.0.0`). Now: `enable_reverse_tunnels = false`, and a listener
  binds `[gateway] reverse_bind_addr` (default `127.0.0.1`); the client's `bind_addr` is ignored.
- **Password login is off, and hashes are Argon2id.** Before: `allow_password = true`; hashes were `sha256:<hex>` of the
  bare password, compared with `==`. Now: `allow_password = false`; `password_hashes` values are Argon2id PHC strings
  with a per-user salt (`printf '%s' "$PASSWORD" | wsh-server --hash-password`), compared in constant time. An unknown
  user and a wrong password now answer identically (`invalid password`) after the same work; `unknown user` is gone.
  **Existing `sha256:` entries are refused**, not accepted with a warning: the server logs, at start-up and by user name,
  that the entry is ignored and how to replace it. (A warning that nobody reads would leave the weak hash live; and
  anyone relying on password login must already edit the config to set `allow_password = true`, which is the moment to
  rehash.)

To get the old behaviour back (not recommended; each line says what it re-opens), put this in `config.toml`:

```toml
[gateway]
enabled = true
allowed_destinations = ["*", "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "::1", "fc00::/7", "fe80::/10"]
enable_reverse_tunnels = true
reverse_bind_addr = "0.0.0.0"

[auth]
allow_password = true
allow_legacy_sha256 = true   # keeps `sha256:<hex>` entries working; logs a DEPRECATED warning at every start-up
```

Most deployments want less than that: `enabled = true` plus `allowed_destinations = ["*"]` is the public internet only;
add `"host:port"` or a range for each internal service a client really needs. A downstream that downloads the release
binaries and relied on the default gateway for egress (the netway `GatewayBackend` pairing) needs at least the first two
lines of the `[gateway]` block above.

### Rust `wsh` CLI (#134, #135, #136)

- **Fix: `wss://` no longer panics (#134).** rustls needs a process-wide crypto provider and the build enables two;
  the first TLS handshake panicked unless `WSH_INSECURE_LOOPBACK_TLS=1` happened to take another path (`-t wt`
  masked it, because that transport installed one). `wsh` installs `ring` at start-up and the client library does
  before every connection (a provider the embedding program installed first is left alone).
- **Fix: output sent in the same burst as `OpenOk` was lost (#135).** The dispatch loop handed `OpenOk` to the opener
  and went on to the next frame; a host that answers at once had already sent the first `SessionData` (even the `Exit`),
  which arrived before the session was registered and was dropped. The loop now notes the channel when it hands over
  `OpenOk`, keeps what follows for it (bounded: 16 channels, 1024 frames and 4 MiB each), and `open_session` replays it in
  order as it registers the session. `echo hi` lost its output in 11 of 40 runs against such a host; it is 0 of 160 now.
  The same path carries a `stdio: "pipes"` stderr channel.
- **Fix: `wsh connect` exits when the session ends (#136).** The terminal input thread blocked in a read nothing could
  cancel, so the runtime waited for a key press. It polls now and stops with the session. A dropped connection also
  ends a session blocked in `read()` instead of leaving it waiting forever.
- **Fix: the per-frame `DEBUGTRACE` lines are gone, and bulk output is fast (#136).** The release build wrote one line to
  stderr per frame, including the whole `SessionData` payload formatted as a list of numbers. 64 MiB through `wsh` took
  about 91 s before (0.7 MiB/s); it takes about 0.1 s now (600+ MiB/s) on the same host and machine; the session read
  path also copies slices instead of popping one byte at a time. Diagnostics go to stderr now (they went to stdout, into
  the command's output), and `channel N exited` is a debug event, not a line on every run. (That `eprintln!` stood in for a
  `tracing` call that hung: the old exec held `stdout().lock()` across its read loop, and `tracing` wrote to stdout.)
- **`wsh host command` forwards stdin, signals and resize (#136).** Stdin that is a pipe or file is sent to the command and
  its end is EOF where the host offers `exec-pipes` (which also keeps stderr apart, on `stderr` instead of in the
  output); elsewhere the bytes are sent but the end cannot be signalled. SIGINT, SIGTERM and SIGHUP are forwarded; the
  same signal twice disconnects (`128 + n`). `--tty` gives the command a terminal and forwards resizes. A command whose
  exit status never arrived (dropped connection) now exits 255 instead of 0. `wsh-client` gains
  `SessionOpts.stdio`, `WshSession::{read_stderr, close_stdin, supports_stdin_eof, has_stderr}`.
  (The Rust `wsh-server` only logged `Signal` at this point; it delivers it now, see the first section.)
- **A full URL is a target (#136).** `wsh wss://host:8443/rendezvous/ab12 command` (also `https://`, `wt://`, `ws://`,
  with `user@` in front or in the URL) dials exactly that, path and query included; `--port` and `--transport` do not
  apply and there is no transport fallback. `ws://` is accepted only for a loopback host. `sessions`, `attach` and
  `detach` reach the same URL again (`last_session.json` gains an optional `url`).
- **Tests:** `test/rust/wsh-cli.test.mjs` runs the built `wsh` against a Node host (`test/rust/fixtures/cli-host.mjs`,
  which answers in the same burst as `OpenOk`) and the real `wsh-server`: TLS without a panic, 160 instant-answer runs
  eight at a time, URL targets, stdin, SIGINT, exit status, bulk output, `connect` under a pty, EOF and stderr against
  `wsh-server`. `test/rust/wsh-rust-server-defaults.test.mjs` runs `wsh-server` with no configuration: gateway and
  reverse listeners refused, the wildcard not reaching loopback, a named rule reaching exactly its address, Argon2id
  login, the `sha256:` refusal. Unit tests cover the OpenOk race, the policy (every restricted range, IPv4-mapped and
  NAT64 spellings, rebinding shape), listener bind, password hashing and the config defaults.

## 0.36.0

- **A host that lives in a page, with the public API only (#131: #114, #115, #132, #133, #116, #128, #130).** An embedder
  ran `createMemoryHost().accept(new WebSocket(...))` in Chromium with the released Rust `wsh` CLI as operator. It worked
  only by wiring the connection factory by hand (deep imports the package did not export), with `dataStreams: false` and an
  injected pty; pty stdin was silently dropped until `globalThis.Buffer` was shimmed; and the bundle dragged in the whole
  client. All of that now works through exported, typed entry points, and CI proves it in a real browser.
  - **`createMemoryHost({ pty, fs, hostKey, dataStreams })` (#114, #132).** `pty` is `node-pty`-shaped (`{ spawn }`); `fs`
    is an object of file operations (`operate`, `readWhole`, `writeWhole`, `writeAt`; `fs: { root }` is refused, it needs
    Node); `hostKey` is a `CryptoKeyPair` (non-extractable is fine), a signer `{ publicKey, sign }`, or `true`; clients
    pin it as for any host. `dataStreams: false` (default `true`, so nothing changes) serves exec as `data_mode:
    "virtual"` and offers neither `stream-announce` nor `rpc`; `accept(socket, { dataStreams })` sets it per connection
    (also on `createWshServer().accept()`). **#132 is an option, not a negotiation:** the released Rust client states
    nothing in `Hello` (only `mcp`, `file-transfer`) that says whether it can open streams, so a host cannot decide.
  - **New entry points `@johnhenry/wsh/host` and `@johnhenry/wsh/reverse` (#115).** `/host` exports the connection
    factory (`createConnectionFactory`, now documented and with defaults; `authorize` is required), `bindSocket`,
    `hostFeatures`, `resolveBackends`, `resolveHostKey`, `buildAuthorizer`, `authMethods`, with types (`src/host.d.ts`).
    `/reverse` is `createReverseHost` for a page or Worker (injected `exec` / `pty` / `fs` / `mcp` only). `./server` is
    unchanged and Node-only, and still exports `createReverseHost` with `exec: true` and `fs: { root }`.
  - **`accept(new WebSocket(url))` works on a socket that is still connecting (#115).** The host speaks first (its QMux
    handshake); those bytes were dropped while the socket was `CONNECTING`. They are now held (at most 256 KiB) and sent
    on `open`.
  - **#133: pty stdin is no longer dropped in a browser.** The pty input path called `Buffer.from(data)`, a
    `ReferenceError` swallowed by an empty `catch`. It now passes a `Uint8Array` (node-pty accepts one), and a failed write
    is logged (`onLog`) instead of swallowed. A pty's `write` therefore receives a `Uint8Array` where it used to receive
    a `Buffer` (a `Buffer` is a `Uint8Array`; `typeof d === 'string'` and `Buffer.isBuffer(d)` checks in a custom `spawn`
    shim are the only things that could notice).
  - **No Node built-in or `Buffer` is reachable from a browser entry point, and `"sideEffects": false` (#128).** The
    connection handler no longer imports `gateway.mjs` (its Node sockets are loaded by `createWshServer`, which passes
    `createGatewaySession` to the factory) or the client (the feature strings moved to `src/features.mjs`, re-exported from
    `client.mjs`). `test/browser-bundle.test.mjs` bundles every entry for the browser with esbuild, fails on a Node
    built-in, `require()` or `Buffer`, and on a bundle more than 10% over `scripts/bundle-budget.json`; `npm run size`
    prints raw / gzip per entry point and single-import probes (CI runs it; `-- --update` rewrites the budget).
    esbuild is a devDependency only (one binary, no dependency tree).
  - **Moved functions (for anyone rebasing):** `createReverseHost` moved from `src/server/reverse-host.mjs` to
    `src/reverse-host.mjs` (renamed, body unchanged apart from taking its backends as a second argument as
    `createReverseHostWith(options, backends)`); `src/server/reverse-host.mjs` is now a 4-line wrapper that builds the
    Node backends. `buildBackends` is now `resolveBackends` (`src/host-backends.mjs`, browser-safe) plus a Node wrapper
    (`src/server/backends.mjs`, same signature and result). `MCP_CALL_ID_FEATURE`, `MCP_CANCEL_FEATURE`,
    `STREAM_ANNOUNCE_FEATURE`, `EXEC_PIPES_FEATURE` moved to `src/features.mjs` (still exported from `client.mjs`).
  - **`npm run test:browser` and a `browser` CI job (#116).** Playwright + Chromium: a browser client against a Node host
    (auth with a non-extractable key, exec, a pty with resize, files, resume); a host in the page joined to its operator by
    a byte pipe, driven by the JS client and by the **released Rust CLI** (downloaded from this repository's `rust-v*`
    release, verified against `SHA256SUMS`, run with `HOME` on a temp directory); `WshKeyStore` with a non-extractable key
    across a reload. `npm test` stays JS-only.
  - **README (#130):** Quick Start uses a non-extractable key; the stale "stands at 0.17.0" preamble is gone; the stale
    codegen path in `spec/wsh-v1.yaml`'s header is fixed; a Related projects section; capability-matrix row and Security
    model entry for a host that lives in a page (what a non-extractable key does not protect, and that a file/pty/exec
    backend confines nothing by itself).
  - **Wire format:** no message, field or feature string was added; `dataStreams: false` selects the existing `virtual`
    data mode. **Defaults changed:** none.
- **Tests:** `test/memory-host-backends.test.mjs` (injected pty / fs / host key; `dataStreams`; no `Buffer` global;
  the exported factory; a still-connecting socket), `test/browser-bundle.test.mjs`, and `test/browser/*.spec.mjs`.

## 0.35.0

- **`createMemoryHost({ rpc, sessions })`: typed RPC channels and detach/resume without Node (viaframe#592).** Both used
  to be `null` in the memory host ("need Node"), so a browser frame could not host either.
  - `rpc: { [protocol]: (channel, ctx) => void }` registers handlers on the stock `RpcChannel`; `rpcMaxMessageBytes`
    (default 1 MiB) and `rpcMaxInflight` (default 64) as for `createWshServer`. Handler functions only: the `wsh-host`
    / `wsh-fs` built-ins and `mcpServerAdapter` stay in `@johnhenry/wsh/server`.
  - `sessions: true | { detachTtlMs, maxDetached, ringBytes }` keeps exec sessions across a dropped link or `detach()`
    and serves `resumeSession()` / `attachSession()` / `listRemoteSessions()` through the same connection handler, so
    the wire behaviour and the existing clients are unchanged. Limits and defaults are the server's (300000 ms, 16
    detached, 1 MiB replay ring per session). Tokens are random per session (no `sessionSecret`).
  - The session store (`ByteRing`, `HostedSession`, `SessionRegistry`) moved from `src/server/sessions.mjs` to the
    Node-free `src/session-registry.mjs`; `server/sessions.mjs` re-exports it and adds the HMAC tokens, so the server's
    behaviour and exports are unchanged. Without the new options the memory host behaves as before, and nothing new
    runs host commands: sessions only wrap the `exec` function the caller passes.
- **Tests:** `test/memory-host-rpc-sessions.test.mjs` (rpc round trip, negotiation and option validation; drop then
  resume replaying only the missed output and the exit; detach/resume; unknown, expired, bad-token, other-principal and
  ahead-of-session resumes refused; the ring bound and the `maxDetached` bound; option validation; exec-free).

## 0.34.2 / Rust `rust-v0.6.0`

- **Rust `wsh-server` implements `McpCancel` and advertises `mcp-cancel` (#110).** A `McpCall` that carries a `call_id`
  now runs as its own task instead of inline in the message loop, so a slow tool no longer holds up the connection and a
  cancel can reach it. `McpCancel { call_id }` aborts that task: the tool's future is dropped and the CLI bridge kills the
  tool's whole process group (the shell and anything it spawned). The call is answered once, with
  `{ success: false, error: "cancelled by the caller" }` (the same reply `@johnhenry/wsh/server` sends). An unknown or
  already-finished id is ignored; a call is never answered twice; calls are independent, and closing the connection
  aborts whatever is still running. A call without a `call_id` (an older client) still runs inline and is answered in
  order, exactly as before. The server now advertises `mcp-cancel` (with `mcp-call-id`), so the stock client starts
  sending cancels to it; clients that never send `McpCancel` are unaffected.
- **`[[mcp.tools]]` in the Rust server's `config.toml`.** The CLI-tool bridge existed but nothing could register a tool
  from the binary. Each entry (`name`, `description`, `command`, `parameters`, `working_dir`, `env`, `timeout_secs`)
  offers `sh -c <command>` with `{arg}` placeholders filled from the call's arguments. No tools by default. Only
  register commands every authenticated client may run.
- The JS package is unchanged apart from README/CHANGELOG. The Rust workspace is now 0.6.0.
- **Tests:** a Rust-suite block (cancel mid-way: the tool and its child process die, no completion marker, exactly one
  reply; a concurrent call survives; unknown and finished ids; a call in flight does not block others; no-`call_id` and
  never-cancelling clients).

## 0.34.1

- **`WshMcpBridge.call(tool, args, { signal })` (#108).** Same contract as `client.callTool`: an already-aborted signal
  sends nothing; aborting rejects with an `AbortError` and, against a host advertising `mcp-cancel`, sends `McpCancel`.

## 0.34.0

- **`AbortSignal` for `upload`, `download` and `callTool` (#108).** `upload(blob, path, { signal })`,
  `download(path, { signal })` and `callTool(name, args, { timeout, signal })` (a number is still a timeout) reject with
  an `AbortError` (`cause` is `signal.reason`) and close the file channel they opened. An already-aborted signal starts
  nothing. `WshFileTransfer` passes `signal` through.
- **Partial uploads.** The JS server buffers an upload and writes the file only when the final chunk arrives, so an
  abort (or any close) before then writes nothing and leaves an existing destination untouched. The server now logs
  `upload <path>: closed before completion, nothing written` (and the same for downloads, where it also stops sending).
  An abort that lands after the final chunk was sent may still complete the write.
- **`McpCancel` (0x44), feature `mcp-cancel`.** An aborted `callTool` sends it so the server stops the tool: the
  handler's `ctx.signal` fires and the call is answered with a failure result the caller discards. Negotiated like
  `mcp-call-id`: the client sends it only to a host advertising `mcp-cancel`, so older hosts (and the Rust
  `wsh-server` before `rust-v0.6.0`, which did not advertise it) are unaffected; there the call is only abandoned locally. Implemented
  in `@johnhenry/wsh/server`. Spec: `McpCancel` (regenerated into all three outputs). Exports `MCP_CANCEL_FEATURE`,
  `mcpCancel`.
- **`client.getSession(id)`.** Returns the live `WshSession` this client opened, by `channelId` or server `sessionId`,
  so a caller that only holds the id from `listSessions()` can `write()` / `closeStdin()` / `close()` it.
  `listSessions()` entries now also carry `sessionId`.

## 0.33.0 / Rust `rust-v0.5.0`

- **Exec on plain pipes with a stdin EOF, for the Rust `wsh-server` (#105).** The Rust server runs exec on a PTY, which
  echoes and rewrites input and cannot signal end of input, so `exec({ stdin })` and `closeStdin()` failed there. It now
  advertises a new `ServerHello` feature, `exec-pipes`. A client that sees it may open an exec channel with the new
  optional `Open.stdio = "pipes"`: the command then runs on plain pipes (byte-exact stdin and stdout, no echo, no
  `\n` -> `\r\n`), and `OpenOk` adds `stderr_channel_id` (the command's stderr arrives as `SessionData` on that
  channel, ahead of `Exit`) and the `stdin-eof` capability (a zero-length `SessionData` from the client closes the
  command's stdin). stderr is not kept for Attach/Resume replay. Spec: `Open.stdio` and `OpenOk.stderr_channel_id`
  (regenerated into all three outputs).
- **JS client.** `WshClient.exec(url, cmd, { stdin })` uses pipes automatically when the host advertises `exec-pipes`,
  and then also returns `stderr`; `exec(..., { stdio: 'pipes' | 'pty' })` and `openSession({ type: 'exec', stdio })`
  choose explicitly (`'pipes'` throws before sending anything if the host lacks the feature). `WshSession.onStderr`,
  `.stderrChannelId` and `closeStdin()` work on such a session. Exports `EXEC_PIPES_FEATURE`.
- **Compatibility.** Negotiated, never assumed (the Rust `Open` decoder rejects unknown fields): a new client against an
  older Rust server never sends `stdio` and still gets the clear "needs a stream-mode session or a host advertising
  exec-pipes" error rather than a hang; an older client against a new server never asks for pipes and gets the PTY
  exactly as before, as do `pty`/shell sessions and `exec` without `stdin`. `@johnhenry/wsh/server` is unchanged (its
  stdin-stream EOF needs no negotiation). The Rust workspace is now 0.5.0.
- **Tests:** `test/exec-pipes-negotiation.test.mjs` (new client + old host, old client + new host, empty writes are not
  EOF) and a Rust-suite block (`cat`, `wc -c`, empty and 8 MiB stdin, binary round trip, stdout/stderr apart, exit code,
  `sh -s`, explicit `closeStdin()`, PTY unchanged).

## 0.32.0

- **`WshClient.exec(url, cmd, { stdin })` and `WshSession.closeStdin()` (#104).** `stdin` is a string, `Uint8Array`,
  `ReadableStream` or (async) iterable; it is written in bounded chunks and stdin is then closed (EOF), so `cat`,
  `wc -c` and `sh -s` work. `session.closeStdin()` does the same on an open exec session without closing the session
  (idempotent; later `write()` rejects). Without `stdin`, nothing changes. No server or wire change: a client-opened
  stdin stream ending was already EOF for `@johnhenry/wsh/server`. Stream-mode hosts only; the Rust `wsh-server`
  (virtual mode, no EOF message) makes `closeStdin()` throw (#105). With `stdin` the primer byte is skipped (the first
  stdin byte or the EOF announces the stream).

## 0.31.0 (2026-10-14)

- **`@johnhenry/wsh/memory`: a browser-safe in-memory host (#99).** `createMemoryHost({ auth, exec, mcp, extensions })` runs
  the real connection handler (handshake, auth, exec channels, MCP tools, extensions) over an in-memory socket pair, so a
  wsh host can run in a page or Worker with no Node, for demos and tests. `host.connect(credentials)` /
  `host.createClient()` give a client wired to it; `host.WebSocket`, `host.accept(socket)` and `createSocketPair()` are the
  pieces. `exec` is a function (there is no shell); `pty`, `fs`, `gateway`, `relay`, `sessions`, `rpc`, `hostKey` and
  WebTransport stay Node-only. To make this possible the connection handler no longer imports `node:crypto`/`node:fs`/
  `node:net` at load (limits moved to `server/constants.mjs`, the gateway loads `node:net`/`node:dns` on first use);
  behaviour is unchanged. `WebSocketTransport` takes an optional `{ WebSocket }` constructor to dial with.
- **`WshClient` signs with a page-held signer (#100).** `connect()`, `WshClient.exec()` and `connectReverse()` accept
  `signer: { publicKey, sign(data) }` (raw 32-byte key or public `CryptoKey`; sync or async `sign`) instead of `keyPair`;
  passing both is a `TypeError`. New helpers `resolveSigner`, `signChallengeWith`, `signPeerRecordWith`. `keyPair` is
  unchanged. `createReverseHost` still needs a `keyPair` (it also uses the private key for end-to-end encryption).
- **`createWshServer().accept(socket, { remote })` takes a pre-upgraded transport (#101).** An already-accepted
  WebSocket-like duplex (a `ws` socket, a browser/Worker `WebSocket`, a test double) is served with the same auth,
  features, rate limit and session registry as `listen()`, so an embedder that owns the HTTP server no longer needs a
  per-session loopback listener (which any local process could connect to). `listen()` is now optional, may be mixed
  with `accept()`, and `close()` drops accepted sockets too.
- **Docs: the recording export is asciicast-v2-shaped, not an asciicast file (#102).** README and `recording.mjs` now say
  the same thing: one JSON document (not NDJSON) with a `sessionId` field, `width`/`height` that follow the latest resize,
  and `open`/`exit` events, so `asciinema play` cannot read it as-is. The README gives the short conversion to a real
  `.cast` file (tested in `test/recording-format.test.mjs`). No behaviour change.

## 0.30.0 (2026-10-08)

- **`createWshServer({ gateway })`: the Node server answers the gateway opcodes (0x70-0x7e).** Until now only the Rust
  `wsh-server` did, so a browser tab using `GatewayBackend` (`@johnhenry/browsermesh-netway`) could not reach a plain-TCP
  service through a Node host. `gateway: { allow, maxConnections?, connectTimeoutMs?, socks? }` serves `OpenTcp` /
  `GatewayData` / `GatewayClose` and `ResolveDns` (A/AAAA). Default deny: `allow` is a list of `"*"`, `"host"` (any
  port) or `"host:port"` patterns matched on the name the client asked for; an empty list reaches nothing. `socks`
  (`"host:port"` or `{ host, port }`) dials through a SOCKS5 proxy such as a local Tor client, handing it the name
  unresolved (no DNS leak, `.onion` works); `ResolveDns` is refused in that mode. UDP (`OpenUdp`) and reverse tunnels
  (`ListenRequest`) get a clean failure. Advertised as the feature `gateway`. The Rust server is unchanged.

## 0.29.0 (2026-10-08)

- **`createWshServer({ tls })` (wss://).** `tls: { cert, key, ca?, passphrase? }` serves the WebSocket listener over
  TLS on the same port (the options of `https.createServer`); `close()` releases it. Previously `wss://` needed a
  TLS-terminating proxy. The WebTransport listener keeps its own certificate (`webTransport`).
- **`createWshServer({ extensions })`.** Handlers for application-defined control messages: a message whose `type` is
  a string (protocol messages are numeric, so there is no collision) from an authenticated connection is handed to
  `extensions[type](msg, { username, fingerprint, send })`; a throw is logged. Lets a host add its own verbs
  (e.g. a Web Push subscription) without forking the connection handler.
- **`relay.onUnreachable(from, targetFingerprint, request)`.** Called (not awaited) when an operator asks to connect
  to a peer that is not registered; the operator still gets `no such peer`. For waking the peer another way.

## 0.28.0 (2026-10-08)

- **Relay: several operators per peer (#89).** `relay: { maxOperatorsPerPeer: n }` (default 1, so nothing changes
  until you ask) lets a peer be bridged to up to `n` operators at once; `createReverseHost({ maxOperators: n })` is the
  other half and serves each operator with its own connection state (channels, processes, files), accepting each on
  its own identity (`accept` runs per operator). Spec additions, all optional on the wire and regenerated into JS and
  Rust: `RelayForward.to_fingerprint` (a peer addresses a reply to one operator; the relay routes it, re-wraps it with
  the peer as sender and never delivers the field), a new `ReverseClose { target_fingerprint, reason? }` (0x57) that
  the relay sends a multi-operator peer when one operator leaves -- it stays registered instead of being closed -- and
  the feature `relay-multi-operator`. The opt-in is negotiated, so nothing older breaks: a relay with the option
  advertises `relay-multi-operator` in its `ServerHello`; a host claims it in `ReverseAccept.features` only after
  reading that; a peer that never claimed it stays held to one operator and is closed when its operator leaves, as
  before. A peer answers one `ReverseConnect` at a time (a concurrent one is `busy: ... retry in a moment`); at the
  cap the reason is `busy: this peer already has its maximum of n operators` (`busyPeerFull(n)`). New client
  surface: `sendRelayControl(msg, { to })`, `onRelayMessage(msg, fromFingerprint)`, `onReverseClose`, and
  `reverseClose()` / `relayForward({ toFingerprint })`; `createReverseHost` gains `operators`. The Rust relay is
  unchanged (still one operator per peer; the new fields parse and are ignored): #93.
- **`createReverseHost` answers `KeyExchange` and does end-to-end encryption (#90).** For a session it has opened, an
  operator's `KeyExchange` (X25519, or X25519+ML-KEM-768 when asked) is answered; that session's output is then sealed
  into `EncryptedFrame`s and its input opened from them (AAD = session id, strict counters, `responder` role tag).
  Plaintext input for an encrypted session is ignored (a relay cannot inject stdin around the encryption); a replayed,
  tampered or spliced frame is dropped without consuming a counter. On by default, `e2e: false` turns it off; the host
  advertises `e2e` / `e2e-sign` in `ReverseAccept.features`. To authenticate the host's half the optional
  `KeyExchange.signature` (spec) carries an Ed25519 signature over the label, session id, algorithm and both
  ephemeral keys (`keyExchangeTranscript()`); `client.initiateE2E(sessionId, algorithm, timeout, { verifyPeer })`
  rejects with `code: 'E2E_PEER_UNAUTHENTICATED'` unless it verifies against the host's key, and reports
  `peerAuthenticated`. The host signs when the relay says it can carry one (`e2e-sign` in its `ServerHello`, which this
  relay now sends) -- a Rust relay older than the regenerated types drops a connection that sends the field -- and
  `e2e: { sign: true | false }` overrides. New exports: `E2E_FEATURE`, `E2E_SIGN_FEATURE`, `keyExchangeTranscript`,
  `verifyKeyExchangeSignature`; the responder lives in `src/e2e-exchange.mjs`. Direct connections (`createWshServer`)
  do not offer it: E2E here is the virtual-mode layer a relay bridge uses.
- **Fixed:** `createReverseHost().close()` left the bridged operators' processes running (the client's own
  `disconnect()` never calls its `onClose`); it now ends every bridge first.
- **Changed:** a reverse host now states `e2e` and `e2e-sign` in `ReverseAccept.features`, so `bridgedFeatures` of a
  host without fs or mcp is `['e2e', 'e2e-sign']` rather than `[]`.
- **Tests:** `test/relay-multi-operator.test.mjs` (routing, drops, caps, `ReverseClose`, per-operator state, cleanup),
  `test/reverse-host-e2e.test.mjs` (relay sees only ciphertext, both hybrid roles, signature checks including a relay
  swapping the host key, plaintext injection / replay / splice / tamper).

## 0.27.1 (2026-10-08) / Rust `rust-v0.4.0`

- **Rust `wsh-server` serves typed RPC channels (#86).** `Open { kind: "rpc", command: <protocol> }` is accepted on
  WebSocket (QMux) connections and the `wsh-host` (`host.info`, `host.ping`) and `wsh-fs` (`stat list read write upload
  download rename mkdir remove`) protocols are served exactly as `@johnhenry/wsh/server` serves them: the same
  `rpc`, `rpc-protocol:<name>` and `rpc-max-message:<n>` features, the same incremental CBOR-sequence decoder with a
  size bound, JSON-RPC 2.0 dispatch with the same reserved codes (-32700 .. -32603, -32000 .. -32003) and messages,
  `$/cancel` and `$/progress`, a per-channel in-flight cap, and `wsh-fs` confined like the JS `fs` option (no `..`,
  absolute-path or symlink escapes -> -32003, read-only, size limit). Streams bind to channels in `OpenOk` order, a
  client `Close` for an rpc channel is no longer mistaken for a session `Close`, and a host-initiated end sends
  `Exit` + `Close`. `kind: "rpc"` is not in the generated `ChannelKind` enum, so it is recognised on the raw control
  message and the spec and codegen are untouched. New `[rpc]` section in `config.toml`; `wsh-fs` is offered only when
  `fs_root` is set, and a key limited to a forced command opens no channel (`wsh-fs` needs the file-transfer scope).
  Not served: the `mcp` protocol (an embedding concern) and the native WebTransport listener. The JS package is
  unchanged apart from this README note. The Rust workspace is now 0.4.0; the `rust-v0.4.0` tag is left to the
  maintainer (release workflow is tag-driven).
- **Tests:** unit tests for the sequence decoder, the engine (cancel, progress, limits, parse errors), `wsh-fs`
  confinement, and channel binding over a real QMux pair; `npm run test:rust` drives the Rust server with the stock JS
  client for `host.info`, a chunked `wsh-fs` read, a cancel, the confinement rules, an oversized message, and rpc
  channels next to an exec session.

## 0.27.0 (2026-10-07)

- **`@johnhenry/wsh/server`: a `selfSigned` WebTransport certificate is rotated (#81).** It used to
  expire (13 days) and make a long-running server unreachable for pinned clients. Now
  `prepareBeforeMs` before `notAfter` (default 3 days, at most a third of the validity) the next
  certificate is generated and `certificateHashes()` publishes `[current, next]`, and
  `activateBeforeMs` before `notAfter` (default 1 hour, at most a sixth) the listener switches to
  it and retires the old hash; the next rotation is then scheduled from the new certificate.
  New on the server: `certificateHashes()` (a `serverCertificateHashes` list, `{ algorithm:
  'sha-256', value }` per hash), `rotateCertificate()` (publish the next hash now; `{ activate:
  true }` also switches now) -- also on `webTransport()`, which gains `certificates()` and whose
  `certificateHash` / `notAfter` follow the certificate being presented. `selfSigned: { rotate:
  false }` restores the old behaviour. The switch restarts the HTTP/3 listener on the same port
  (the native transport cannot swap a certificate in place and presents one at a time), so live
  WebTransport sessions end and clients reconnect; the WebSocket listener is untouched. A client
  that pinned the overlap list survives the switch, one with only the old hash must re-pin. The
  client already accepted several pinned hashes; the README documents the re-pin flow
  (publish `certificateHashes()` over a channel the client trusts, refetch on failure, retry
  once). A certificate you supply is never rotated (`rotateCertificate()` rejects).
- **Fixed:** `generateSelfSignedCertificate({ validityDays })` with a validity under a few hours
  produced a certificate that had already expired (the one-hour back-dating exceeded it); the
  back-dating now shrinks with the validity.
- **Tests:** forced short validity (a 12 s window): publication ahead of expiry, the automatic
  switch, a client pinned to the overlap list connecting after the switch and after the old
  `notAfter`; manual `rotateCertificate()` / `{ activate: true }` (both pinned work before the
  switch, the next one alone does not, the old one alone fails after, live sessions end, same
  port); supplied certificates and closed listeners.
## 0.26.0 (2026-10-07) / Rust `rust-v0.3.0`

- **Relay: E2E can cross a bridge (#80).** `KeyExchange` and `EncryptedFrame` are now on
  the spec's `relay.forwardable` list (regenerated into JS and Rust), so two endpoints bridged
  through the Node or the Rust relay can run `initiateE2E()` and exchange sealed frames; the
  relay carries them as opaque bytes and holds no key (a test checks it never sees the
  plaintext). `KeyExchange` is unauthenticated, so this defeats a relay that only observes,
  not one that substitutes keys; the README says so. Key exchange from an unbridged connection
  is still never carried. The Node host (`createReverseHost`) has no E2E layer and does not
  answer `KeyExchange`: tracked in #90.
- **Relay: one operator per peer, now explicit.** Several operators would need a recipient on
  `RelayForward` and a bridge-ended notice (a spec addition shared with Rust), so the limit
  stays and is tracked in #89. `ReverseReject.reason` is now `busy: this peer already has an
  operator ...` (`BUSY_PEER`) or `busy: you already have a bridge ...` (`BUSY_OPERATOR`)
  instead of a bare `busy`; clients matching `=== 'busy'` should match the `busy` prefix.
- **Relay: client feature gates read the bridged host (spec, additive).** `ReverseAccept` gains
  an optional `features: string[]` (the host's own, in the vocabulary of `ServerHello.features`).
  `createReverseHost` states them (`reportFeatures: false` leaves them out); the relay forwards
  them after bounding (<= 64 strings of <= 128 characters, otherwise dropped); after
  `reverseConnect()` the client's `hasFeature()` / `features` answer from them, with the new
  `bridgedFeatures` (`null` when no bridge or the peer did not say, then the relay's features
  apply as before) and `serverFeatures` (always the relay's). `fileWrite()` / `fileRename()`
  therefore work through a relay without `fs`, and refuse locally when the *host* lacks them.
  The Rust crates: `ReverseAcceptPayload.features` is `Option<Vec<String>>` (the codegen now
  emits `Option` for an optional array too; no other field was affected), and
  `ReverseAccept` is `deny_unknown_fields`, so a **Rust peer or relay older than `rust-v0.3.0`
  rejects a `ReverseAccept` that carries `features`**; set `reportFeatures: false` against one.
- **Tests:** `test/server-relay-bridge.test.mjs` (E2E key agreement and sealed frames both ways
  with the relay's view recorded, key exchange not carried unbridged, both busy reasons, the
  peer freed after its operator leaves, bridged feature gates in every combination, bounding,
  reset on disconnect); one cross-implementation test against the Rust relay (features forwarded,
  `KeyExchange` both ways). The relay test that asserted `fileWrite()` refusing through a relay
  without `fs` now asserts it working.

## 0.25.1 (2026-10-07) / Rust `rust-v0.2.0`

- **Rust `wsh-server` honours `Resume.last_seq` and sets `AttachmentInfo.channel_id`/`seq` (#79).**
  Per-session state now lives in the session, not the connection that opened it: a PTY/exec
  session has one output pump that appends to its ring buffer (the byte count is `seq`, as in
  0.21.0) and fans out `SessionData` to every attachment, so the process keeps running and
  keeps filling the ring after its connection drops. `Resume` replays only the bytes after
  `last_seq`; a `last_seq` older than the 256 KiB ring still holds, or newer than the session
  produced, is an `Error` (code 4) naming the gap. Attach/Resume answer with a Presence whose
  entry for the caller carries the assigned `channel_id` and the `seq` of the first byte on it,
  then the replay and live output arrive as `SessionData` on that channel (not `GatewayData`
  id 0), in order. Read-only attachments (`mode: "readonly"`, also read-only guest joins)
  cannot write, and a connection can no longer write to a channel that is not its own
  control attachment. Connections going away detach; a session that ends while detached
  lingers (not counted against a key's `max_sessions`) until the next attach replays it and
  delivers `Exit`/`Close`. The ring buffer, which was never actually written before, now is.
- **Tests:** `cargo test` unit tests for the ring positions and the session manager (replay
  from `last_seq`, gaps, pruning, write permission, exit while detached); five new cross-
  implementation tests in `test/rust/wsh-rust-server.test.mjs` drive the Rust binary with
  the stock JS client (drop the socket, resume from a fresh connection: same pid, only later
  bytes, live afterwards; Attach channel/seq; gaps; exit while detached; read-only viewer).
- **Docs:** spec and README no longer say the Rust host ignores `last_seq`. The Rust
  workspace is versioned independently: this change is `rust-v0.2.0`; the npm package gets a
  patch release only for the documentation.
## 0.25.0 (2026-10-07)

- **New: typed ("object-mode") RPC channels as a subsystem (#85).**
  `client.openRpc(protocol, { timeoutMs })` (sugar over `openSession({ type: 'rpc', protocol })`)
  opens an ordinary QMux stream whose payload is a CBOR sequence (RFC 8742) of JSON-RPC 2.0
  messages; `createWshServer({ rpc: { [protocol]: handler } })` serves them. Requests are
  correlated by `id` only (the fix class for #72), either side may request, `$/cancel { id }`
  answers `-32001` and aborts the handler, `$/progress { id, chunk }` streams results, and closing
  the stream rejects pending requests with `-32001` / `channel-closed`. Negotiated through
  `ServerHello.features` (`rpc`, `rpc-protocol:<name>`, `rpc-max-message:<bytes>`); the client
  refuses an unadvertised protocol with `UNSUPPORTED_PROTOCOL` before sending anything. No control
  message, spec or Rust codegen change: `Open { kind: 'rpc', command: <protocol> }` (the `Open`
  message has no dedicated field, so the protocol name rides `command`).
  New exports: `RpcChannel`, `RpcError`, `RPC_ERROR`, `RPC_FEATURE`, `rpcProtocolFeature()`,
  `parseRpcFeatures()`, `CborSequenceDecoder` (incremental, size-bounded, reuses the existing CBOR
  codec), `RpcMcpTransport` / `mcpClientTransport()` / `mcpServerTransport()`; server:
  `mcpServerAdapter()`, options `rpc`, `rpcMaxMessageBytes`, `rpcMaxInflight`.
- **First protocols.** `wsh-host` (`host.info`, `host.ping`); `wsh-fs` (`stat list read write upload
  download rename mkdir remove`, same confinement / `readOnly` / `maxFileBytes` as `fs`, reads
  streamed as `$/progress` chunks, policy refusals `-32003`); and `mcp`, which closes #71: an MCP
  SDK `Server` is exposed with `rpc: { mcp: mcpServerAdapter(server) }` (an SDK `Transport`
  implemented over the channel; MCP is already JSON-RPC, so it is a pass-through apart from
  `notifications/cancelled` <-> `$/cancel`) and an MCP `Client` consumes it with
  `mcpClientTransport(await client.openRpc('mcp'))`. The SDK is never imported by this package;
  `@modelcontextprotocol/sdk` is an optional peer (and a dev dependency for the tests).
- **Client prefers `wsh-fs`.** When a host advertises `rpc-protocol:wsh-fs`, `fileStat` /
  `fileList` / `fileRead` / `fileWrite` / `fileRename` / `fileMkdir` / `fileRemove` go over it
  (results keep the `FileResult` shape; `client.preferRpcFiles = false` opts out) and fall back to
  `FileOp` otherwise. This is the control-plane file path #72 was a correlation bug in; it stays
  for compatibility with the Rust server.
- **Not done / follow-ups.** The Rust `wsh-server` does not serve `rpc` sessions or the built-in
  protocols (it does not advertise `rpc`, so clients fail fast); tracked on the Rust side. #68
  (`session.attach`) and #69 (relay control) are the natural next protocols and are not part of
  this release.
- **Tests:** `test/rpc-codec.test.mjs` (CBOR-sequence decoding over split and concatenated
  buffers, size limits, binary), `test/rpc-channel.test.mjs` (out-of-order correlation, cancel,
  late responses, close, progress, limits), `test/rpc-server.test.mjs` (negotiation, `wsh-host`,
  `wsh-fs` confinement / `readOnly` / size limit / chunked reads, the stock file API over
  `wsh-fs`), `test/rpc-mcp.test.mjs` (`initialize` -> `tools/list` -> `tools/call`, in-flight
  cancel, server-initiated requests, with the real SDK); `test/types/rpc.ts`; example 06.
- **Docs:** README "RPC channels (object mode)" and the capability matrix row.

## 0.24.0 (2026-10-07)

- **New: `podId()`, `fingerprintToPodId()` and `podIdToFingerprint()` are exported from the package
  root, with typings (#66).** `podId(rawPublicKey)` is base64url(SHA-256(raw key)), the BrowserMesh
  identity, and equals `@johnhenry/browsermesh-primitives`' `derivePodId(cryptoKey)` /
  `PodIdentity.podId` for the same Ed25519 key; it is the same hash as `fingerprint()` in a
  different encoding, and the two converters re-encode between them. They already existed in
  `src/auth.mjs` but were unexported and untyped (0.18.0 had said they would stay private).
  `fingerprintToPodId()` now throws a `TypeError` on a value that is not an even-length hex string
  instead of silently producing a wrong ID from non-hex input.
- **Tests:** `test/pod-id.test.mjs` checks parity against `@johnhenry/browsermesh-primitives`
  0.2.0 (new devDependency) for generated keys and `PodIdentity`, round-trips and refuses bad
  input; `test/types/pod-id.ts` type-checks the declarations. README documents the helpers.

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
