# wsh over a caller-supplied duplex

Status: implemented in `@johnhenry/wsh/duplex` (`createDuplexSocket`, `serveWshOverDuplex`, `connectWshOverDuplex`). Nothing is added to the wire.

## What this is for

A full wsh session (login, host-key proof, the sealed session, channels) over a duplex of messages that another library provides: a browsermesh
channel between two pods, a `MessagePort`, a data channel. Two things it makes possible: a browser with no relay can be reached by hopping
through a mesh peer, and a pod can reach a wsh host without a relay. wsh knows nothing of the library that provides the duplex.

## What already existed, and what this adds

The transport wsh runs over a WebSocket is QMux records on a stream of binary messages (`src/transport-ws.mjs`), and a host serves any
WebSocket-shaped object it is handed (`host.accept(socket)`, `bindSocket`). So the session needs no new protocol: only a WebSocket-shaped object
whose messages are the duplex's. That is `createDuplexSocket`. The rest is policy, because a duplex somebody else carries is not a TLS connection:

- the session over it is **sealed** unless said otherwise (the host serves nothing until it is; the client refuses a host that cannot);
- the client must **name the host key** it expects;
- `sealSession: 'require'` can now be asked for per connection (`bindSocket(..., { sealSession: 'require' })`, `host.accept(socket, { sealSession: 'require' })`):
  it can only strengthen the host's own setting, and a host that cannot seal (no host key, or data streams) refuses to attach the connection at all.

## What the duplex must guarantee

1. **Reliable, in order, no duplicates.** The bytes of a QMux record and of a sealed frame arrive in the order sent, none lost, none twice. (A
   hop may do worse; see below: what it can do is limited to ending or stalling the session, not changing it.)
2. **Messages of bytes.** Each message is a `Uint8Array` / `ArrayBuffer`. Text is refused (the link ends).
3. **A maximum message size** that both ends know (`maxMessageBytes`, default 64 KiB). A write larger than it is cut into messages of at most
   that size and a message larger than it ends the link. Where the cuts fall does not matter: the transport above reads a byte stream and
   reassembles records. (A mesh channel with a smaller limit sets it smaller; a pipe relay carries 4 MiB.)
4. **Backpressure by a returned promise.** `send` may be asynchronous; the next message is not written until it settles, and what waits is bounded
   (`maxBufferedBytes`, default 4 MiB): over it the link is ended rather than buffered without bound. A `send` that throws or rejects ends the link.
   Inbound, what arrives before anyone listens is held, bounded by the same figure.
5. **One connection per duplex.** A duplex carries one session. When it ends (the peer left, the channel closed) the caller calls `end()`; when
   the session ends it calls the duplex's `close`.
6. **Open before use.** The host speaks first (its transport handshake). The caller must have wired `receive` before the far side can send, or hold
   what arrives until it has: a message for an end that does not exist yet is the caller's to keep (a mesh adapter has the channel before the client).

Ordering matters more than delivery: a duplex that reorders, or repeats, a record corrupts the byte stream and the session ends; one that drops
a message stalls it until a timeout. Neither lets anything through that was not sent.

## Channel binding: what there is, and what there is not

There is **no TLS** on this transport, so there is no `cert-hash` and no `tls-exporter` binding to the connection. What carries the
authentication instead:

- **The host-key proof.** The host signs a challenge that names this session and the client's nonce with its host key; the client checks the
  signature and compares the key with the one it expects (`expectHostKey`, or a `known_hosts` entry; over a mesh, the peer's pod id is the key's hash,
  so `expectHostKey: podIdToFingerprint(peer)`). A hop that answers as the host would have to hold that key.
- **The login bound to the host key.** `requireChannelBinding: ['host']` (the one binding a memory host has): the client's signature covers the host
  key it proved, so a hop that relays a genuine login to a different host, or the host's challenge to a different client, produces a signature
  the real host rejects. This is the default of `connectWshOverDuplex`.
- **The sealed session.** After login a signed key exchange (X25519 and ML-KEM-768, both halves signed by the login key and the host key) keys an
  authenticated encryption of every message but the keepalive, with a role tag and a counter: a frame that does not open ends the session, a
  replayed, reflected or reordered one does not open, and an unsealed message after sealing is dropped.

## What a hop on the duplex can and cannot do

It **cannot**: read a command, an output, a file, a credential, a tool call or an object value after login; change one without the session
ending (or the message being dropped: nothing altered is delivered); replay a message so that it runs twice; log in as the client or serve as the
host to a client that named the host key; make a client that required sealing talk unsealed, or make a host that requires it serve a plain client.

It **can**: see that a session exists, when it starts and ends, and the size and timing of messages; drop or delay messages (the session
stalls; there is no integrity of availability); end the link; refuse to carry it. It reads the **handshake**, which is plain before the seal: the
host's key (public), the client's username, the client's public key and the features each side states.

It is **not protected against**: a client that does not name the host key (it trusts the first host that answers, `trustOnFirstUse: true`,
said out loud, and that is the one moment a hop can answer as the host); a **password** login (the password is sent before the session is sealed,
so `connectWshOverDuplex` refuses one unless `allowUnsealed: true`); the host's own configuration (what the key may do is the host's `auth`,
capabilities and allow-lists, not the duplex's); an endpoint that is itself hostile (sealing protects from the hop, not from the peer).

## Unsealed

`allowUnsealed: true` on either function lifts the seal requirement and the default binding. Nothing a hop does is then caught: it can read and change
everything. It is for a duplex that is already protected by something else, and it is said in the call.

## Not covered here

Discovery, and who the peer is (the mesh's business: it must give the key to expect); relaying through several hops (each hop is another
duplex, and the session is end to end); reconnecting a session over a new duplex (a `resume` of an exec session works as over any connection;
the duplex itself is one connection).

## Compatibility

No message, field or feature string is new. A released peer on the other end of a duplex is an ordinary wsh peer: a 0.48.0 client or host
interoperates (it seals as it always did); the Rust client and server are not bound to a duplex by this change (the Rust CLI dials a pipe
relay, which carries bytes the same way, with `--via`, and `wsh --sealed`).
