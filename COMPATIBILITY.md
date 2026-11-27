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
