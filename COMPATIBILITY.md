# Compatibility policy

How the wsh protocol and its two implementations (the npm package `@johnhenry/wsh` and the Rust crates `wsh-core`, `wsh-client`,
`wsh-cli`, `wsh-server`) change without breaking a peer somebody already runs. It describes what the repository already does, and it is
the checklist for a change to `spec/wsh-v1.yaml`, to a default, or to a file format that two implementations both read.

Which message each implementation actually handles is [`spec/message-matrix.md`](spec/message-matrix.md) (generated; CI fails when it is
stale). What each side can do beyond the messages is the README's [capability matrix](README.md#rust-implementation).

## Versions and what a release may change

- The two implementations are versioned separately: the npm package by `package.json` (`vX.Y.Z` tags), the Rust workspace by `Cargo.toml`
  (`rust-vX.Y.Z` tags). The wire protocol is `wsh-v1` (`Hello.version`); it does not change inside a major version of the protocol.
- **The packages are 0.x.** A minor version of either may add features and may tighten what a peer accepts. It does not change what a
  message already on the wire means. Anything that can break an existing deployment is listed in the CHANGELOG as **breaking**, with who is
  affected and what to do, in the release that makes the change, never silently. A change of a DEFAULT is such a change.
- **Before 1.0 the supported combination is "the latest release of each side, and the one before it".** Older peers are kept working
  where it costs nothing and where the rules below make it free; no peer is promised beyond the last two releases of its implementation.
  Every CHANGELOG entry that touches the wire has a **A released peer** paragraph saying what an older client, host, relay or Rust
  binary does with the change; a change without one is not finished.
- Release binary names (`wsh-<target>` archives under a `rust-vX.Y.Z` release) are an external contract; do not rename them
  (AGENTS.md).

## The rules for a wire change

### 1. A new field is optional on decode, and omitted on encode when unset

Every field added to an existing message is optional: the codec treats a missing value as "not sent" (`required: false` in the spec; in Rust
`Option<T>` with `#[serde(default, skip_serializing_if = "Option::is_none")]`, or a defaulted `Vec`). A message built without the field is
byte-for-byte what the previous release built. A new message type is an addition of its own; nothing that existed refers to it. A field
that is **required** may only be on a message that is itself new.

### 2. What a released peer does with something it does not know

This is the half of the rule that is not symmetric, and it is why a new field is never simply "added":

- **JS** decoders and handlers ignore a field they do not know and log and ignore a message type they do not know. A released JS host
  that is sent `Open.target` runs the command on its default target: the field is silently ignored, which is wrong when the field was a
  request for something specific.
- **Rust** payload structs are `#[serde(deny_unknown_fields)]` (every generated payload struct). A released Rust peer that receives a
  known message with a field it does not know **fails to decode it**: the message is refused, and on some paths (the relay, a reverse
  connection) the connection is dropped. A message type it does not know fails the same way. So a new field on an existing message is
  safe against a released Rust peer only if that peer never receives it.

So one of two things must be true of every addition, and the CHANGELOG entry says which:

1. **It is gated by a feature string** (rule 3), or
2. a released peer ignoring it is harmless, and a released Rust peer never receives it (it is only ever sent to an implementation that
   cannot be a released Rust peer, or it travels in a place the Rust types do not cover, such as a `features` string list or an
   opaque `json` value).

Counter-examples this repository has paid for: `ReverseAccept.features` was rejected by every Rust peer and relay older than
`rust-v0.3.0` (hence `reportFeatures: false`); `McpCall.call_id`, `Open.target`, `ReverseConnect.features` and
`KeyExchange.signature` were each added with a feature string because the Rust types would have rejected them.

### 3. A feature string gates anything a released peer would reject or silently ignore

- A host states what it can do in `ServerHello.features` (and, behind a relay or a bridge, `ReverseAccept.features`); the other side sends
  the new field or message **only** to a peer that stated the feature. Examples: `mcp-call-id`, `mcp-cancel`, `targets`,
  `relay-multi-operator`, `relay-gateway`, `e2e-sign`, `operator-proof`, `e2e-sealed`, `e2e-session`, `exec-pipes`, `stream-announce`. The names live in
  `src/features.mjs` and next to their handlers in the Rust crates; add the new one to both and to the README's capability matrix.
- The receiving side of a feature is built before the sending side is turned on, and a peer that did not state the feature is never
  sent it, **even when it is probably fine**: a peer that predates the feature can only be assumed to reject or ignore it.
- "Silently ignores" is as dangerous as "rejects", and harder to see. If a released peer would ignore a restriction, a requirement or
  a request and carry on, the feature gate must also make the new sender refuse to proceed against a peer without it (a sealed bridge
  fails with a sentence when the peer does not state `e2e-sealed`: nothing is sent that a peer could take as unsealed).
- **A feature string is not a version number.** It says "this peer does this one thing". Do not infer one from another, and do not
  gate a new thing on the version string.
- A feature that changes a default or turns something on is opt-in (an option on the host or the client), unless the old behaviour is
  a defect; then it is a breaking change and is called out as one.

### 4. The hazard outside the codec: the same input read by two implementations

The `capabilities=` / `expires=` options of 0.44.0 show the case rule 2 does not cover. They are not wire messages: they are text in an
`authorized_keys` file that a Node host and a Rust server both read. A released Rust server (`rust-v0.14.0`) **ignored an option it did
not know and served the key everything**; a released Node host skipped any line with options. Nothing was rejected, so no feature string
could have protected anyone. The only remedies are on the side that can still change:

- **Parsing is fail-closed.** An option that is not in the table, a malformed value, a duplicate, a stray comma, a differently-cased name
  keeps the key off the allowlist and logs a stable code (`unknown-option`, `bad-syntax`, `bad-value`, `duplicate-option`). It is never
  "skip it and grant the rest". This holds for every restriction-bearing input, on both implementations, and a new option is added to
  both parsers and to `spec/key-options.vectors.json` (run by `test/key-options.test.mjs` and `cargo test`) in the same change.
- **State the hazard in the release notes**, with the exact thing not to do: "do not put these options in a key file read by a released
  Rust server". A restriction a released peer cannot enforce is a security note, not a footnote.
- The same input read by two implementations gets shared test vectors, not two hand-written test files.

The same rule applies to any option, config value or CLI flag that narrows what a peer may do: an unknown value is an error at start
(the host refuses to start, the key is refused, the command exits 2), never ignored.

### 5. Defaults deny; relays and peers are not trusted

Everything from the network is untrusted and bounded, and a default that allows something is a security decision that needs a CHANGELOG
entry and a README line in the Security model section (what it does NOT protect against). A new default that is more permissive than the
last release is breaking in the sense of rule "versions" above even when no deployment would notice.

### 6. A change is not done until it is tested against the released peer

- New fields and messages: a test that the old shape still decodes, and that the new sender does not send to a peer without the feature
  (`test/server-parity.test.mjs`, `test/cross-compat.test.mjs`, `test/operator-proof-compat.test.mjs` are the examples).
- Anything the Rust side reads from JS-written data, or the other way round: shared vectors, and `npm run test:rust`
  (`test/rust/*.test.mjs` drives the real `wsh-server` with the JS client).
- If you change `spec/wsh-v1.yaml`: `npm run codegen`, then the matrix with `npm run matrix`; `npm run codegen:check` and
  `npm run matrix:check` are both CI gates.

### 7. CBOR is written canonically, read strictly, and the two decoders are one rule set (#317, #325, #326)

**Written.** Both encoders (`cborEncode` in `src/cbor.mjs`; `cbor_encode`, `frame_encode` and the rpc encoders in `crates/wsh-core/src/cbor_canon.rs`) write the deterministic form of RFC 8949 section 4.2.1 and nothing else, so one value has one byte string, and the two encoders write the same bytes: map keys sorted by the bytes of their encoding (shorter first, then bytewise; for text keys the UTF-8 length, then the UTF-8 bytes; `type` is no longer first), the shortest integer head, the shortest float that reads back exactly (half, single, double; one NaN, `f97e00`; `-0` is `f98000`), definite lengths only. `spec/cbor-vectors.json` records what each encoder writes for every message (`js` and `rust`: canonical, and byte-equal to themselves after a decode and a re-encode in either language; `js_released`: npm 0.62.x; `rust_released`: rust-v0.26.2) and `test/rust/cbor-differential.test.mjs` holds the two encoders to each other on 3000 random values and on the vectors. The JS encoder also takes a BigInt (exact, `-2^64 .. 2^64-1`).

**Read.** A message is accepted only if it is exactly one well-formed CBOR item with no non-canonical *head* (integers, lengths) and none of the constructs listed below. What is canonical beyond that (key order, float width, NaN, integers a JS number cannot carry) is a separate set of rules with its own switch, `legacyNonCanonical`, because the released encoders did not write it: see "The compatibility window and its sunset" below. `cborDecode` (`src/cbor.mjs`) and `cbor_decode` /
`cbor_strict::validate` (`crates/wsh-core/src/cbor_strict.rs`) refuse, with the same rule code (`CborError.code`, `StrictCode::as_str()`), the
same inputs (`spec/cbor-strict-cases.json` is the shared table; `test/rust/cbor-differential.test.mjs` compares the two on 20000 mutations):

| Rule | Code |
|---|---|
| a declared string, byte-string, array or map length past the end of the buffer (an array needs a byte per element, a map two per pair; checked before anything is allocated) | `length-exceeds-buffer` |
| a head or item cut off | `truncated` |
| a byte after the top-level item (`cborDecodePrefix` / `item_end` read one item out of a longer buffer) | `trailing-bytes` |
| an integer or length that is not in the shortest form of its head | `non-shortest` |
| an indefinite-length string, array or map (except the legacy exception below); a break outside one | `indefinite-length`, `unexpected-break` |
| reserved additional info (28 to 30; 31 on integers and tags) | `reserved-additional-info` |
| a map key twice in one map; a map key that is not text | `duplicate-key`, `non-text-key` |
| any tag; any simple value but `false`, `true`, `null` | `tag`, `simple-value` |
| a text string that is not UTF-8; nesting deeper than 128 | `invalid-utf8`, `too-deep` |

| Rule (canonical; refused only with `legacyNonCanonical: false` / `strict`) | Code |
|---|---|
| a map whose keys are not sorted length-first, then bytewise | `non-canonical-key-order` |
| a float that is not in the shortest width that reads back exactly: a float32 that fits a float16, a float64 that fits a float32; any NaN but `f97e00` (no payload, no sign); an infinity or a zero in a wider form | `non-canonical-float` |
| (JS only) an integer outside `+-(2^53-1)` with `unsafeIntegers: 'refuse'` | `unsafe-integer` |
| (always) more than 1,000,000 arrays and maps in one item (`CBOR_MAX_CONTAINERS`, `cbor_strict::MAX_CONTAINERS`) | `too-many-containers` |

How each gap #325 listed is handled:

1. **Key order** and 2. **float width**: required in canonical mode, as above; both encoders now write the canonical form.
3. **NaN payloads and -0**: a NaN with a payload or the sign set is `non-canonical-float` in canonical mode, and the encoders write one NaN. `-0` is canonical (`f98000`) and stays `-0` in JS.
4. **JS integers above 2^53**: an integer a JS number cannot carry is read per `unsafeIntegers`: `'round'` (the released behaviour, the nearest double; the default of the window), `'bigint'` (exact, a BigInt; the differential uses it, and the Rust decoder reads these exactly), `'refuse'` (`unsafe-integer`; what `strict` selects: a message field is a JS number and cannot carry it, and refusing is better than silently rounding). No message field has to carry one (audit, #336): the spec has 34 `u64` fields (none is `i64`; the two `i32` fields are 32-bit) and none can reach 2^53 (9.0e15) in use. Byte counts, offsets and sizes (`Resume.last_seq`, `AttachmentInfo.seq`, `FileOp`/`FileChunk` offsets and sizes, `FileEntry.size`, `Metrics.memory`, `RateControl.max_bytes_per_sec`, `RateWarning.queued_bytes`) would need 9 PB; the echo and terminal counters (`echo_seq`, `frame_seq`, `base_seq`), `PolicyUpdate.version` and `Ping`/`Pong` `id` are counters that both implementations start at 1 (JS `++pingId`, Rust `ping_id += 1`; `Pong` echoes the id); timestamps and durations (`CommandJournal.timestamp` in milliseconds, `FileEntry.modified`, `PeerInfo.last_seen` and the `*_secs` fields in seconds, TTLs, `rtt`, `expires_in`, `retry_after`) stay below 2^53 for about 285,000 years (milliseconds) or longer. **One caveat: the signed peer record's `seq`** (`ReverseRegister.seq` and `PeerInfo.seq`; `seq` in `build_peer_record_transcript` / `auth.mjs`): the spec calls it the signing peer's own monotonic counter, "in practice current-time-millis", and both implementations write milliseconds (about 1.8e12), but nothing bounds it, so a peer that counted microseconds (about 1.8e15, still below 2^53) is fine and one that counted nanoseconds (about 1.8e18) is not: JS `'round'` would read it rounded and the signature over the rounded value would not verify, and `strict` would refuse it as `unsafe-integer`. Proposed, not done here because it is a spec statement and not a code change: say in `spec/wsh-v1.yaml` that a record `seq` MUST be at most 2^53-1 (so every JS peer reads it exactly), or, if a wider counter is wanted, have the JS reader take these fields as BigInt (`unsafeIntegers: 'bigint'` for the record fields only), which changes no bytes on the wire.
5. **JS float/integer conflation**: *not changed, and it cannot be without breaking released peers.* `f93c00` (1.0) and `01` read as the same JS number, because a JS number has no integer/float split and message fields are plain numbers; a decoder that returned a wrapper for floats would break every field. The JS encoder never writes an integral number as a float. The Rust typed decoder keeps the split: an integer field refuses a float (`f93c00` in a `u64`), and ciborium also refuses an integer in an `f64` field, so a JS peer that sends an integral number in one of the three `f64` fields (`cpu`, `confidence`, `load`) is refused by Rust. That predates this change and is unchanged; it is also the one place the two encoders differ for the same value (a Rust `f64` 1.0 is `f93c00`, JS 1 is `01`). Tested: `cbor_canon::tests::float_is_not_integer_in_typed_decode`, `test/cbor-canonical.test.mjs`.
6. **`cborDecodePrefix`** with an offset that is not in the buffer throws (done in #324); the legacy indefinite map is now read at offset 0 only (see below).
7. **A container-count cap**: 1,000,000 arrays and maps per item, on in every mode (a 4 MiB frame of empty arrays was 4 million containers, about 160 MiB of heap and 2.4 s). A real message is orders of magnitude below it (20,000 records of three containers each is 60,000); `maxContainers` overrides it in JS, and `Options::max_containers` (`Options::with_max_containers`) in Rust, where `FrameDecoder::with_options` and `decode_envelope_with` take the options (a `FrameDecoder::new()` reads with the defaults, as before).

**The options are checked (#336).** In JS a decode option of the wrong type throws a `TypeError`: `strict`, `legacyIndefiniteMap` and `legacyNonCanonical` must be booleans (or absent), `unsafeIntegers` one of its three strings, `maxContainers` a positive integer; `strict: 1` was silently "not strict". A `FrameDecoder` checks them in its constructor.

**The one legacy exception.** Every released `wsh-core` encoder wrote a message envelope as an **indefinite-length map** (`0xbf ... 0xff`):
`Envelope` has a `#[serde(flatten)]` payload, which makes serde ask for an unsized map and ciborium write the indefinite form. All 110
message types did this (`spec/cbor-vectors.json`, `rust_released`), so refusing it would refuse every message a released `wsh`,
`wsh-server` or `wsh-client` sends. Decoders therefore accept an indefinite-length map as the **top-level item** (`legacyIndefiniteMap`,
default true), at **offset 0 only** (`cborDecodePrefix` and `item_end` read it at the start of a buffer and refuse it after another item or at any other offset), and nowhere else; what is inside it is held to every rule above. The Rust encoder in this tree writes a definite-length
map (`Envelope` serializes by hand, generated from `spec/codegen.mjs`), so the exception is only for peers that predate it. It goes away with the rest of the
window, below. The rpc channel (a CBOR sequence of JSON-RPC messages) never had the exception: no released encoder wrote
an indefinite-length rpc item, and its decoders refuse one.

### The compatibility window and its sunset (#326)

The decoders have three legacy switches, all on by default today and all off in `strict` mode (JS `strict: true`, Rust `Options::strict()`): `legacyIndefiniteMap` (a Rust peer up to rust-v0.26.2 wrote an indefinite top-level map), `legacyNonCanonical` (npm up to 0.62.x wrote insertion order and float64; Rust up to v0.26.x wrote field order; a Rust NaN may carry a sign), and the `unsafeIntegers` default (`'round'` in the window, `'refuse'` in strict mode). `strict` is what every test and the differential run, and what the default becomes. An explicit option beats `strict`. The rpc channel never had the indefinite map (its decoders pass `legacy_indefinite_map: false` / `legacyIndefiniteMap: false`) and keeps `legacyNonCanonical` on for the same window, because released rpc peers wrote non-canonical key order and float64 too.

The window is rule "versions": the latest release of each side and the one before it. The first releases that contain this change write canonical bytes: the next Rust minor (assumed rust-v0.27.0) and the next npm minor (assumed 0.63.0). Then:

| Step | When | What |
|---|---|---|
| 0, this change | now | Encoders canonical; decoders canonical-capable; defaults unchanged: every released peer is read |
| 1, the window closes | the later of: the second Rust minor after rust-v0.26 is published (rust-v0.28.0, when 0.26.x is no longer "the one before the latest"), and the second npm minor after 0.62 (0.64.0, likewise) | No code change. Both release notes say the flip is next. The flip waits for the *later* of the two because `legacyNonCanonical` is also for released JS peers, not only for the Rust ones #326 is about |
| 2, the flip | the first minor of each side published after step 1 | The default becomes strict (`legacyIndefiniteMap` and `legacyNonCanonical` false, `unsafeIntegers: 'refuse'`). A CHANGELOG line says so, as breaking for a released peer. `legacyIndefiniteMap: true` / `legacy_indefinite_map: true` and the other options stay as an opt-in for a deployment that still has an old peer |
| 3 | the minor after the flip | The last minor that has the options |
| 4 | the minor after that | The options and the exceptions are removed: the decoders are strict, with no switch |

A new encoder's bytes need nothing from this: every released decoder reads them (key order and float widths are just data to it; checked against npm 0.62.2 and rust-v0.26.2 when this change was made). What the window protects is a new decoder reading an old encoder.

**What happens on a decode error** (the frame is delimited by its length prefix, so the stream stays in step): the Rust server and client close the session (they read frames with `feed_raw` and `decode_envelope` and end on the first error); the JS WebSocket server logs the error and drops the frame, and handles the good frames around it; the JS WebSocket client emits the error (`onError`) and continues; the JS WebTransport client does the same since this change (before it left its read loop and the connection half-open), and so does the JS WebTransport server. An oversized claimed length ends the connection everywhere. On a sealed session a dropped frame is a gap in the strict counter, so the next frame ends the session. `FrameDecoder.feedAll` is the helper the JS transports share: it returns every good message and every error of a chunk. `FrameDecoder.feed` throws at the first bad frame, with the messages before it in `error.decoded`.

**An older peer.** What the released encoders write is recorded and checked: `test/cbor-vectors.test.mjs` (the JS encoder before and after the canonical change, the current Rust
encoder and the released Rust encoder, every message type), `scripts/cbor-interop-old.mjs` (the encoder of an older `@johnhenry/wsh` install
against this decoder: 0.47.0 to 0.62.2 are byte-identical to this encoder over 291 values; 0.0.0 to 0.45.0 differ only for the value 2^64,
which they wrote as the non-canonical zero `1b 00..00`, for -2^63 (one too low) and for -0 (as 0): bugs fixed in 0.47.0, in values no wsh message carries). A peer written by someone else that emits indefinite lengths, non-shortest integers, tags
or duplicate keys is refused: that is the change, and it is listed as breaking in the CHANGELOG.

## Worked case: the gateway through a relay (`relay-gateway`, #289)

`OpenTcp`, `OpenUdp`, `ResolveDns`, `ListenRequest` and their answers (`DnsResult`, `ListenOk`, `ListenFail`, `ListenClose`, `InboundOpen`,
`InboundAccept`, `InboundReject`; the spec's `relay.gateway_forwardable`) were not on `relay.forwardable`, so no relay carried them. They
are **not added to that list** (every released relay and client reads it): they are a second list, carried only by a relay that lists
`relay-gateway` in its `ServerHello.features`, only for a bridge whose peer stated `relay-gateway` in `ReverseAccept.features`, which a
peer does only when its owner gave it a gateway AND the relay lists the feature. No message or field is new, so a released Rust peer's
`deny_unknown_fields` decoders are not involved: what changes is who is SENT what. "Released" below is npm 0.59.1 and earlier, Rust
`rust-v0.23.1` and earlier.

| Operator | Relay | Reverse host | What happens |
| --- | --- | --- | --- |
| new | new | new, gateway on | The feature is stated at both ends; the requests cross; every connection is metered (credit is implied). A host starts a gateway only when its owner chose how identities are taken (operator proof, or an explicit trust of the relay's word) and, on the Rust CLI, named the operators. |
| new | new | new, gateway off (the default) | The host states nothing; the relay carries nothing; `openTcp()` rejects locally (`this host does not support TCP egress`); a request sent anyway is dropped by the relay, nothing is dialled. |
| new | released | any | The relay does not list the feature, so the host (new) states no gateway and serves none, and the operator sends nothing (`openTcp()` rejects locally). Where the host stated features without the feature, the operator refuses with "does not state relay-gateway" and sends nothing. |
| new | new (`carryGateway: false`, `carry_gateway = false`) | new | As the row above: the relay does not list the feature, nothing is stated or carried. |
| new | new | released | The released host never states the feature, so the relay carries none of it to it; the operator refuses locally. A released Rust CLI host with `--capability gateway` (it had handlers since 0.22, unreachable) stays unreachable. |
| released JS | new | new, gateway on | A released JS client sends `OpenTcp` / `OpenUdp` (its own check is the host's `gateway` feature, which a new host states), the relay carries them, and **TCP and UDP flows work** (`GatewayOk`, data, credit and close were always forwardable). `ResolveDns` and `ListenRequest` are carried and answered, but the answers (`DnsResult`, `ListenOk`, `InboundOpen`) are not on the released client's list and are dropped there: they time out. A released client does not seal them, so on a sealed bridge the host drops its requests. Use a new client. |
| released Rust | any | any | A released Rust operator has no way to open a gateway connection over a bridge (`wsh reverse-connect` has no forwarding), so nothing changes. |
| any | released | new | Nothing changes for what the relay already carried. |

A host that serves several operators at once cannot seal their bridges on the Rust side (one seal per connection), so a Rust CLI gateway
for several operators is always "the relay's word about who is asking" and needs `--relay-gateway-trust-relay`. Ordering inside one
stream: the JS QMux stream now writes one call at a time, in call order (concurrent writers used to interleave their chunks once a
write waited for the window); a released JS peer that wrote concurrently could corrupt its own control stream, and a new peer reading
it is unchanged.

What is tested: both relays against both host implementations, a host that states the feature on a relay that does not carry it, a relay
that carries it for a host that did not state it, sealed bridges, and an operator that sends where it is not carried
(`test/relay-gateway.test.mjs`, `test/rust/wsh-reverse-host-half-close.test.mjs`, `test/rust/wsh-relay-gateway.test.mjs`, the `bridges`,
`reverse_gateway` and `common` unit tests). Not tested against a release binary: the released-client row (stated from the code: its
inner-type check is `isRelayForwardable`).

## Worked case: the gateway over a network the embedder supplies (#299)

A host in a page (`createMemoryHost({ gateway: { network } })`), a browser-safe reverse host, or a Node host given `gateway.network`
serves the gateway opcodes over the embedder's network instead of the machine's. **Nothing is added to the wire**: no message, no field,
no feature string. The host states what a gateway host has always stated, and only what it can serve: `gateway` when the network can serve any of
TCP, UDP, DNS or listening (a released client checks `gateway` for all four, and a TCP open on a network without `connectTcp` is refused with
a sentence), `gateway-credit`, `gateway-endpoints` when it has named endpoints, and `gateway-datagram` only over a transport that has datagrams
(WebTransport; an in-page host's has none) and when the network has `openUdp` with UDP on (so UDP rides datagrams over an injected network too, and
the host DROPS what a sink cannot take). It answers with the codes and sentences a Node gateway does. On the machine's gateway `udp: false` now
means off (it threw before), so a host with UDP off no longer states `gateway-datagram`; a released client then uses the reliable path or is
refused, as for any host without UDP. So a peer cannot tell this host from a Node host with a gateway:

| Peer | What happens |
| --- | --- |
| released JS client (0.45.0 and later) | Reads `gateway` and `gateway-credit` as it does from a Node host: `openTcp()`, `openUdp()`, `listenTcp()`, the raw `ResolveDns`, with flow control. Nothing it does not know is sent to it. |
| released Rust peer (`rust-v0.16.0`, `deny_unknown_fields`) | Nothing new is sent: the messages are the existing gateway ones. A released CLI that forwards (`-L host:port`) over a pipe relay to an in-page host with a gateway reaches the injected network the same way it reaches a Node host's. |
| a reverse host with `gateway.network` behind a relay | Exactly the `relay-gateway` rows above (the feature is `relay-gateway` as before; the host states it only on a relay that lists it). A released relay or operator behaves as there. |
| a host older than this one | Has no `gateway.network`; there is nothing to negotiate: the option is the host's own, an operator sees only the features the host states. |

What differs between hosts is local policy, not wire: on an injected network `udp`, `dns` and `reverse` are each off until the embedder
turns them on and the network has the method; on the machine's network UDP and DNS are on with the gateway (unchanged). A refusal
carries the same `GatewayFail` code 4 (policy) with a sentence that says which switch or method is missing. Tested: `test/gateway-network.test.mjs`
(direct, through a pipe relay, a Node server, a reverse host behind a relay) and `test/browser/gateway-network.spec.mjs` (Chromium).
Not tested against a release binary of the Rust CLI: stated from the wire, which this adds nothing to.

## Worked case: the lossless close, `gateway-lossless-close` (#286)

**One feature string, one reason text, no message and no field.** A side that understands the `GatewayClose` reason `released` ("I will read
nothing more and send nothing more; deliver what you already sent, in order, then finish") states `gateway-lossless-close`: a client in
`Hello.features` (the Rust client always, the JS client unless `gatewayLosslessClose: false`), a host in `ServerHello.features` (a gateway on
`wsh-server` and the Node servers, unless `lossless_close = false` / `losslessClose: false`); behind a relay, the host in `ReverseAccept.features`
and the operator in `ReverseConnect.features`. A side sends `released` **only to a peer that stated it** (and only when it holds an answering
socket that half-closed and vanished, see the README), so a Rust decoder with `deny_unknown_fields` is never given anything new: the feature is a
string in a list that already exists and the reason is the existing optional text of `GatewayClose`.

| Host | Client / operator | What happens |
| --- | --- | --- |
| new | new | The feature is stated at both ends. The answering side (an origin the host dialled, a reverse forward's local service) is watched once half-closed; one that vanished releases its connection (`GatewayClose` `released`), one that closed completely after its whole answer loses nothing. |
| new | released (0.61.0 JS, `rust-v0.25.0`) | The client does not state the feature, so the host does not send `released` and does not watch origins: exactly the behaviour before this change (an origin that vanished after its end of file is held until the client closes or the idle bound; one that closed completely loses nothing). Tested with `gatewayLosslessClose: false`, which is what a released client's `Hello` looks like. |
| released | new | The host does not state the feature, so the client never sends `released` and does not watch a reverse forward's local service: as before. Tested with `losslessClose: false` / `lossless_close = false`. |
| new | new, through the JS relay | The operator states the feature in `ReverseConnect.features` only when the relay lists `relay-gateway` and the host's registered record lists `gateway` (a host that can decode the field: a released peer of rust-v0.6 to v0.8 drops a connection on a field it does not know). The relay passes it on to a host that lists `gateway` (only that string) or `operator-proof` (the operator's features whole). A released JS relay (0.60.0, 0.61.0) strips it unless the host lists `operator-proof`: then nothing is negotiated and nothing changes. |
| new | new, through the Rust relay | The Rust relay already carries `ReverseConnect.features` (bounded) unchanged: the released one too (`rust-v0.25.0`), so it carries this. |
| new host | operator that did not state it, through a relay | The host sees no `gateway-lossless-close` in the request: it does not acknowledge, and its origins behind this bridge are not watched. |
| new | new, through a relay that DROPS the operator's statement (a released JS relay, 0.60 / 0.61, for a host without `operator-proof`; or a hostile one) | The host never sees it, so it does not list `gateway-lossless-close-ack`; the operator, which relies on the feature behind a relay only with that answer, does not either. Both sides are on the earlier behaviour (tested). |
| new host | operator that did not state it, through a relay that ADDS a statement, on a bridge with NO proof (`trustRelayIdentity` / `--relay-gateway-trust-relay`, or an operator without a key) | The host believes it, acknowledges and watches, and sends `released`; the operator did not state the feature, so it treats `released` as an ordinary reason (a half-close as a first close, ignored as a second): nothing is lost, its connection waits for its own close or the idle bound (tested, pinned as unchanged). With no operator signature there is nothing to authenticate the statement with; the relay is trusted for identity on such a bridge. |
| new host | operator that did not state it, through a relay that ADDS a statement | On a SEALED bridge the host acts only on what the operator signed: nothing was signed, so it does not acknowledge, watch or release. On an unsealed bridge it is best-effort as before (the relay's list is taken; see the #318 table). |
| any | the Rust `wsh reverse-connect` operator | It does not state the feature, so behind a relay it never gets the lossless close. A Rust reverse host can decline to state or acknowledge it with `--no-lossless-close`. |

### The lossless-close guarantee is SEALED-ONLY (#318): the combinations

The guarantee ("a vanished origin ends the connection without dropping what was sent") holds on a **sealed** bridge only. On an unsealed bridge no carrier
can stop a relay forging or stripping the plain `GatewayClose{reason:"released"}`, so nothing there is reported as a guarantee; it stays best-effort.

On a sealed bridge an operator that states `gateway-lossless-close` **signs the statement into its proof**: the label of the signed bytes becomes
`wsh-operator-proof-v2` and the statement is appended (a proof that states nothing stays byte for byte the v1 proof of 0.62.x). It does so only for a
host whose **verified** registered record lists `gateway-lossless-close-signed` (a record whose signature does not verify is not believed, so a relay
cannot add the string), which a host lists when it reads such a proof and states the feature: a host that does not (0.62.x, or one declining the
feature) would not verify a v2 proof, so it is never sent one. The string is a capability, not a wire field: it rides in a list that already exists, and
a peer that does not know it ignores it. The operator reports the connection as lossless (`lossless === true`) only then; the host acts on
`signedFeatures` of the verified proof, never on the unsigned list, and the unsigned `-ack` is ignored on a sealed bridge.

An unsealed bridge (or none that is proven): nothing is signed (a v1 proof, as 0.62.x). The host behaves as in 0.62.x / rust-v0.26.x (the relay's list is
taken, `-ack` is sent, the origin is watched and released), the operator reports `lossless === false`, and a `released` it receives ends the connection
promptly (what was sent is delivered first), whether or not it negotiated it, instead of holding it to the idle bound (the #318 symptom).

| Operator | Host | Bridge | Relay | Result |
| --- | --- | --- | --- | --- |
| new | new | sealed | honest | Signed (v2 proof), negotiated, released; `lossless` true. |
| new | new | sealed | adds the statement; operator declined it | Not believed: no acknowledgement, not watched, not released. |
| new | new | sealed | strips the statement only, or the `-ack` | The signature carries it: negotiated, released; `lossless` true. |
| new | new | sealed | strips `operator-proof` (and adds the statement) | A sealed host refuses the bridge. |
| new | new | proven but unsealed | honest | Best-effort: released, `lossless` false, nothing signed. |
| new | new | unsealed or no proof | adds or forges the statement or a `released` | The host (relay's list) may watch and release; the operator reports no guarantee and ends promptly on the `released`. Nothing is lost beyond what a relay can always do. |
| new | new | unsealed or no proof | strips the statement | Not released (held, best-effort); no guarantee. |
| new | 0.62.x | any | any | The record lacks the capability: the operator states it unsigned as before. Nothing fails; best-effort, `lossless` false on a bridge. |
| 0.62.x | new | sealed | honest | The unsigned statement is not acted on by a sealed host: no release, the bridge works. |
| 0.62.x | new | unsealed or no proof | honest | Earlier behaviour: the unsigned statement is taken as stated and acknowledged. |

What is not covered: on an unsealed bridge everything about the release is relay-editable (a relay can also close the bridge). A hostile relay that adds
`gateway-lossless-close-signed` to the record of a 0.62.x host is not believed by a new operator (the record's signature does not verify). Rust
`wsh reverse-connect` states nothing, so it signs nothing. A Rust re-attach that overwrites the active request (#327) is separate and harmless for #318
now that the guarantee is sealed-only.

**Behind a relay the negotiation is two-sided, with one more string:** `gateway-lossless-close-ack`, listed by a host in `ReverseAccept.features` only
when it actually received the operator's `gateway-lossless-close`; a peer that does not know it ignores it (an unknown entry of a list of strings: the
JS and Rust clients and relays read `features` as plain strings, verified by the tests that pass it through both relays and both hosts).
| a connection of an injected network (#299) | any | Never probed (there is no kernel to ask): unchanged, it ends when the network closes the stream; the feature is still stated, and a `released` close from the peer is understood. |

What is tested: both ends new and each end declining (both implementations: `test/gateway-lossless-close.test.mjs`,
`test/half-close-probe.test.mjs`, the `lossless` and `gateway` tests of `wsh-core` / `wsh-client`, `test/rust/wsh-half-close-probe.test.mjs`,
`test/rust/wsh-reverse-forward-full-close.test.mjs` for the Rust `wsh -R`), through the JS relay and the Rust relay to a JS host and to the Rust CLI
host (`test/relay-gateway.test.mjs`, `test/rust/wsh-relay-gateway.test.mjs`, `test/rust/wsh-reverse-host-half-close.test.mjs`), a TCP and a unix
origin, 3 MiB through each, a slow reader, and an origin that vanished. Not tested against a released binary of either implementation: the old
side is simulated by not stating the feature.

## Worked case: a per-operator gateway grant on the Rust CLI reverse host (#296)

**Nothing is added to the wire.** The scoping is command-line flags of the host; what an operator sees is what it saw: `relay-gateway`,
`gateway` and `gateway-credit` in `ReverseAccept.features` (stated for every operator of a host that has a gateway, since the relay keeps the
statement per peer connection), and, for an operator no rule reaches, the existing `GatewayFail` (code 4) for each request with the sentence
"this reverse host has no gateway rule for this operator". A released JS client or Rust peer decodes it as any policy refusal; a released
relay carries it as before. A host older than this one has one list (it would read `FINGERPRINT=RULE` as a destination rule and, by its own start-up check, refuse one that does not parse; not tested against a released binary).

## Worked case: a grant that runs out ends its gateway connections, and a peer that leaves ends its operators (#297)

**Nothing is added to the wire**: no message, field or feature string. When the `expires` of a key (or of what `authorize()` / a reverse
host's `accept()` granted) passes, the host sends each open gateway connection of that holder a `GatewayClose` with the reason
`key expired` and then a second one with the reason `discarded`, and stops its reverse listeners (no message exists for that). On the Rust relay, a
peer that stated `relay-gateway` and leaves has each of its operators sent the existing `Shutdown` message (reason: the bridge is over), after
which the relay closes the operator's connection (the JS relay always closed it, without a message).

| Peer | What happens |
| --- | --- |
| released JS client (0.45.0 and later) | The first close is an ordinary half-close from the host (the application sees the end of its stream); the second is the documented "discarded" and frees the connection at once on a client that has that wording (0.58.1 and later); an older client ignores it and its own half-close bounds free the connection. A `Shutdown` from the Rust relay makes it disconnect (it did so for any `Shutdown`). |
| released Rust peer (`rust-v0.16.0`, `deny_unknown_fields`) | Nothing new is sent: `GatewayClose.reason` is a field every release decodes, and `Shutdown` is a message every release decodes (the Rust client logs it; a Rust CLI operator stays up until its own bridge handling ends it). A peer that ignores a second `GatewayClose` for a connection it already saw close does so as it always did. |
| released relay | Unchanged: the JS relay already closed the operators of a peer that left; a Rust relay of an older release leaves them connected. |
| released host (no expiry cut) | Keeps the connections open past the expiry, exactly as before. |

Not covered: a Rust relay and a peer that did not state `relay-gateway` (the operator stays connected, as since #93); the Rust CLI reverse host
(it has no grant with an expiry). Tested: `test/gateway-expiry.test.mjs`, the `expiry` tests of `crates/wsh-core/src/gateway/session/tests.rs`,
`test/rust/wsh-gateway-expiry.test.mjs`, `test/rust/wsh-relay-peer-left.test.mjs` and the `bridges` unit tests.

## What this policy does not promise

- No peer older than the previous release of its implementation is tested. The CHANGELOG says what an older one does where it was known.
- A message that is in the spec is not thereby implemented: see the matrix. A client author should rely on a message only where the
  matrix shows the host they target names it, and on the field-level behaviour only as far as `test/spec-conformance.test.mjs` and the
  interop tests cover it.
- The wire format of a message that no implementation names may still change before one does. A message every implementation names is
  frozen by the rules above.
