# wsh and browsermesh

[browsermesh](https://github.com/johnhenry/browsermesh) has the counterpart of this page (`docs/wsh-and-browsermesh.md` there). This one is written from wsh's side: what wsh
exports for browsermesh, what it checks, and what it has not seen. It describes wsh 0.59.0 and the browsermesh packages published on npm on 2026-11-26 (refreshed from wsh 0.52.0).
It is a guide, not a protocol; the protocol documents are the other files in this directory.

## What each is for

**wsh** is the authenticated, capability-scoped door into one machine or one page. A client logs in with an Ed25519 key (optionally over a session sealed end to
end), and the host gives that key what its `authorized_keys` line says: `exec`, `pty`, files, a TCP gateway, MCP tools, the remote-object protocol
(`wsh-objects`) on a page. It has a Node and browser implementation and a Rust `wsh-server` that serves a subset (no `wsh-objects`, no named endpoints, no
execution targets).

**browsermesh** is the peer fabric: pods with Ed25519 identities that find and talk to one another, with a capability registry per pod. One is a way into a place; the
other is the way between places.

**wsh does not depend on browsermesh.** `@johnhenry/browsermesh-primitives` is a dev dependency of this repository (`^0.5.0`), used by a test of the pod id derivation
(`test/identity.test.mjs`) and the gateway code table test (`test/gateway-errors.test.mjs`). Every package below that depends on wsh at all does so as a peer or a dev dependency, never the other way (apps and ingress have none of their own).

## Which browsermesh packages build on wsh

Read from the published packages (`npm view`, and the tarballs' `package.json` and `src/`), not from their READMEs.

| Package (version) | Relation to wsh | wsh entry points and exports it imports |
| --- | --- | --- |
| `@johnhenry/browsermesh-objects` 0.1.5 | peer `@johnhenry/wsh >=0.49.0 <1.0.0` (and `@johnhenry/browsermesh-apps >=0.21.0 <1.0.0`); dev dependency `^0.57.0` | `@johnhenry/wsh/objects`: `createObjectsServer`, `createObjectsClient`, `createDuplexPeer`; `@johnhenry/wsh/identity`: `normalizeIdentity` |
| `@johnhenry/browsermesh-mcp` 0.2.4 | peer `@johnhenry/wsh >=0.49.0 <1.0.0` (and `@johnhenry/browsermesh-apps >=0.21.0 <1.0.0`); dev dependency `^0.57.0` | `@johnhenry/wsh/page`: `webmcpTools`, `serveMcpOverDuplex`; `@johnhenry/wsh/identity`: `podIdToFingerprint` |
| `@johnhenry/browsermesh-transport` 0.12.3 | optional peer `@johnhenry/wsh` (`*`; dev dependency `^0.57.0`); the wsh code is behind its `/wsh` subpath (`./wsh`, and `./wsh-in-process` for tests), off unless constructed | `@johnhenry/wsh`: `WshClient`, `WebSocketTransport` (the peer link dials with them: `connect`, `sessionSealed`, `openEndpoint`); `/memory`: `createMemoryHost`, `createSocketPair`; `/page`: `webmcpTools`, `exposeObjects`; `/duplex`: `serveWshOverDuplex`, `connectWshOverDuplex` (the services and the relaying pod); `/pipe-relay`: `createPipeRelay` (in-process) |
| `@johnhenry/browsermesh-netway` 0.4.0 | no runtime import and no peer; dev dependency `^0.57.0` | none: `GatewayBackend` is handed a `WshClient` and uses its `state`, `onGatewayMessage` and `sendControl` |
| `@johnhenry/browsermesh-apps` 0.28.0 | none of its own; `createMeshNode({ wsh })` reaches wsh through the transport's `/wsh` subpath | none directly |
| `@johnhenry/browsermesh-primitives` 0.7.0 | dev dependency `^0.52.0`; no runtime import | none: it implements the same conversions (see Identity) |
| `@johnhenry/browsermesh-egress` 0.3.2 | optional peer `@johnhenry/wsh >=0.55.0 <1.0.0` (dev dependency `^0.57.0`), needed only by its `./node` entry; the consumer entry imports no wsh | `@johnhenry/wsh/address-guard`, loaded dynamically by `./node` (`nodeDialer`): `dialChecked`, `dialUdpChecked`, `resolveChecked`, `isPublicAddress`, `checkAddress`. The package says it classifies no address itself; every decision about a destination address is wsh's. It does not run a wsh gateway |
| `@johnhenry/browsermesh-ingress` 0.6.0 | no peer on wsh and no wsh import; it asks only whether a link was a wsh peer link | none: it reads `node.wsh.links` (the transport's `WshPeerLinks`) to label a link's identity `verified: 'wsh'` (key-authenticated in both directions, sealed), as against `'bound'` or `'key'` |
| `@johnhenry/browsermesh-meshctl` 0.1.0 | optional peers `@johnhenry/wsh >=0.55.0 <1.0.0` and `@johnhenry/browsermesh-transport` (dev dependency `^0.55.0`); no wsh import of its own | none directly: `--wsh-relay` reaches a host through a pipe relay over the transport's `WshPeerLinks` (sealed, key-authenticated, the host pinned to the pod id asked for), so wsh is used through `@johnhenry/browsermesh-transport/wsh` |

The pieces, from the browsermesh side: the sealed **wsh peer link** (`WshPeerLinks`, a link between two pods is one wsh session carrying one endpoint), **`WshServices`** (a stock
wsh client using a pod's objects and MCP tools), and the **relaying pod** (`WshRelay`: a pod carrying another pod's wsh session to a target, granted per target as
`wsh-relay:<target>:open`). The wsh-side seams they use are the duplex binding ([`duplex-binding.md`](duplex-binding.md)), the memory host, `onSealed` and the
caller identity `{ username, fingerprint, podId }`.

## One capability notation

[`capabilities.md`](capabilities.md) says what a capability list means (grammar, wildcards, order of checks, fail-closed on what it does not understand), and
[`capabilities.vectors.json`](capabilities.vectors.json) is that as data. The JS evaluation is `permits` in `@johnhenry/wsh/capabilities`, the Rust `wsh-server` runs the same vectors, and the files ship in the
npm package (`@johnhenry/wsh/spec/capabilities.vectors.json`). browsermesh's registry has scopes of its own; for the forms the two share it is run against these vectors
(`packages/browsermesh-apps/test/capability-vectors.test.mjs` there, with `REQUIRE_WSH_VECTORS=1` in its test script). The forms that coincide:

| wsh key capability | mesh scope |
| --- | --- |
| `objects:ROOT[:get\|call\|set\|on]` | the same string (check: `objects:ROOT` with the operation) |
| `mcp:TOOL` | `mcp:TOOL` (browsermesh-mcp spells the action: `mcp:TOOL:call`, `mcp:TOOL:list`) |
| `rpc:NAME` | `protocol:NAME:open` |
| `expires="..."` | a grant's `expiresAt`; both refuse at the instant (`now >= expires`) |
| `exec`, `pty`, `fs:*`, `gateway:*`, `unix:*`, `endpoint:*`, `target:*`, `relay` | none: machine rights are not granted from mesh trust |

Differences on purpose: wsh has no `rpc:*` and refuses `objects:ROOT:*` (`bad-capability`); a wsh list with only `rpc:wsh-objects` means every root, while the mesh asks for
the protocol and a grant per root and action. The mesh side keeps the full table in its `docs/capability-notation.md`.

## Identity: a wsh key and a pod id

A pod id is `base64url(SHA-256(raw Ed25519 public key))` (43 characters). A wsh fingerprint is the same hash in hex (64 characters). An OpenSSH `ssh-ed25519` line is the key itself.
`@johnhenry/wsh/identity` converts, and browsermesh-primitives has its own copy of the same functions (compared against this one in its tests):

| | wsh (`@johnhenry/wsh/identity`) | browsermesh-primitives |
| --- | --- | --- |
| pod id to fingerprint | `podIdToFingerprint` | `podIdToFingerprint` |
| fingerprint to pod id | `fingerprintToPodId` | `fingerprintToPodId` |
| raw key to OpenSSH line | `rawKeyToOpenSsh` | `openSSHPublicKeyFromRaw` (`PodIdentity#toOpenSSHPublicKey`) |
| OpenSSH line to raw key | `openSshToRawKey` | `rawPublicKeyFromOpenSSH`, `podIdFromOpenSSHPublicKey` |
| an `authorized_keys` line | `authorizedKeyLine` | `authorizedKeysLine` (`PodIdentity#toAuthorizedKeysLine`) |

Checked here: on a fresh key, `podIdToFingerprint(podId(raw))` equals `fingerprint(raw)`, `fingerprintToPodId` inverts it, and an OpenSSH line round-trips to the raw key.

**Both directions are possible and never automatic.** Nothing in wsh writes a key into `authorized_keys` for a pod, and nothing in browsermesh does either. A pod's key often lives in
browser storage; listing it on a machine lets whoever can use that browser profile reach the machine. In the peer link a dialler logs in as `pod_<pod id>` and the host
checks that name against the hash of the key wsh authenticated, so the link needs the equality, not a key shared with a machine.

## The gateway failure table both share

`GatewayFail.code` is one table, in [`gateway-fail.vectors.json`](gateway-fail.vectors.json) and exported from wsh as `GATEWAY_FAIL` and `GATEWAY_FAIL_TABLE`. `@johnhenry/browsermesh-netway` keeps its
`GATEWAY_ERROR` equal to it (a parity test compares them there) and decodes what `GatewayBackend` receives; the Rust client checks the same file.

| Code | Name | Sent by |
| --- | --- | --- |
| 1 | `CONNECTION_REFUSED` | node, rust |
| 2 | `HOST_UNREACHABLE` | node, rust |
| 3 | `DNS_FAILED` | node |
| 4 | `POLICY_DENIED` | node, rust |
| 5 | `GATEWAY_DISABLED` (also read as a timeout from an older node gateway) | rust; node before 0.52.0 sent 5 for a timeout |
| 6 | `CLOSED` | node |
| 7 | `QUEUE_FULL` | node, rust |
| 8 | `TIMEOUT` | node (0.52.0 on) |

A reader that gets a 5 says "disabled, or a timeout from an older gateway"; a number it does not know is reported as unknown, not guessed. A code is never reused or renumbered.

## Which versions go together

wsh **0.59.0** with the browsermesh packages published when this was written: apps **0.28.0**, transport **0.12.3**, primitives **0.7.0**, netway **0.4.0**, objects **0.1.5**, mcp **0.2.4**,
egress **0.3.2**, ingress **0.6.0**, meshctl **0.1.0** (all current on npm at the time). The declared ranges allow it: objects and mcp ask for wsh `>=0.49.0 <1.0.0` and apps `>=0.21.0`; transport asks for wsh `*` and primitives
`>=0.6.0`; egress and meshctl ask for wsh `>=0.55.0 <1.0.0` (egress also apps `>=0.21.0` and netway `>=0.3.0`); ingress asks for apps `>=0.21.0` only; apps asks for transport `>=0.6.0` and primitives `>=0.5.0`. The packages that list wsh as a dev dependency (what that repository installs for its own tests) are on `^0.57.0` (objects, mcp, transport, netway, egress), `^0.55.0` (meshctl) and `^0.52.0` (primitives); apps and ingress list none.
Two floors inside transport: its services (`WshServices`) need wsh 0.50 or later, and its peer link says it needs 0.45. The netway codes need wsh 0.52.0 on the sending side to
send 8 for a timeout; against an older Node gateway netway reads a 5 as described above.

## What is not verified

- **I did not run any browsermesh package.** The table and the ranges above come from `npm view` and from reading the published tarballs and their READMEs (`npm pack`, `package.json`, `src/` and the READMEs of egress, ingress and meshctl for the rows added in the 0.59.0 refresh); the claims about what the browsermesh test suites do (the capability
  vectors, the netway parity test, a netway test against `createWshServer`) come from reading their test files at `origin/main`, not from running them.
- **No browser.** What is run on the wsh side is in Node; the wsh peer link, `WshServices` and the relaying pod are exercised in browsermesh over in-process pipe relays and real wsh handshakes, by its own
  account, not in a browser against the real relay server. browsermesh's page says which of its pieces were run in Chromium, Firefox and WebKit; wsh has not repeated them.
- **This repository's own browser tests** (`npm run test:browser`, which load no browsermesh package) were not run for this page.
- **The Rust `wsh-server` has none of the object work**: no `wsh-objects`, no named endpoints, no execution targets. A key line with an `objects:` entry is refused at load there.
- **The conversions** are checked in this repository with `@johnhenry/browsermesh-primitives` 0.5.0 (what its dev dependency installs), not with 0.7.0, and only on valid keys here; browsermesh's
  own test compares malformed input.
- **A key moved between a pod and a machine** was never tried against a running `wsh-server` or `sshd` by anything here.
