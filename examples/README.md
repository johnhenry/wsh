# wsh examples

Small, self-contained, runnable demonstrations of wsh behavior. Every example runs headless under plain Node (>= 26, as `package.json` `engines` says) with no network, no server, and no dependencies — protocol peers are simulated in-process, exchanging the same wire bytes a real transport would carry.

Run one with `npm run example:01` (etc.), or all of them with `npm run examples` (every `examples/[0-9]*.mjs`, which CI runs).

| Example | Demonstrates |
|---|---|
| [`01-frames-survive-fragmented-transport.mjs`](./01-frames-survive-fragmented-transport.mjs) | Length-prefixed CBOR frames reassemble intact no matter how the byte stream is fragmented in transit. |
| [`02-tampered-challenge-fails-authentication.mjs`](./02-tampered-challenge-fails-authentication.mjs) | Ed25519 challenge-response: the transcript binds signatures to username + session + nonce, so replays, forged nonces, relabeled identities, and impostor keys are all rejected. |
| [`03-handshake-to-exec-over-in-process-pipe.mjs`](./03-handshake-to-exec-over-in-process-pipe.mjs) | A full HELLO → CHALLENGE → AUTH → OPEN(exec) → SESSION_DATA → EXIT conversation in wire format, with pre-auth channel opens refused. |
| [`04-recording-replays-with-original-timing.mjs`](./04-recording-replays-with-original-timing.mjs) | Session recording round-trips through asciicast-v2-compatible JSON and replays with inter-event timing preserved. |
| [`05-remote-mcp-tools-called-through-bridge.mjs`](./05-remote-mcp-tools-called-through-bridge.mjs) | MCP tools on a remote host are discovered and invoked over the control channel, with undiscovered tools rejected client-side. |
| [`06-rpc-requests-answered-out-of-order.mjs`](./06-rpc-requests-answered-out-of-order.mjs) | Typed RPC channels (JSON-RPC 2.0 over a CBOR sequence): a fast answer overtakes a slow one yet each caller gets its own result; `$/progress` chunks and `$/cancel`. |
| [`07-remote-objects-over-memory-host.mjs`](./07-remote-objects-over-memory-host.mjs) | Remote objects (`@johnhenry/wsh/objects`): values, an event, a handle and a callback over a memory host; a key holding `objects:window:get` can read `window`, is refused calls and sets, and does not even see the other root. |
| [`08-page-host-webmcp-via-wsh-mcp.mjs`](./08-page-host-webmcp-via-wsh-mcp.mjs) | A page host serves its allow-listed WebMCP tools behind a pipe relay; the real `wsh-mcp` bridge lists them and calls one, while a consequential tool nobody approved and an unlisted tool are refused. |
| [`09-sealed-session-through-a-hostile-pipe-relay.mjs`](./09-sealed-session-through-a-hostile-pipe-relay.mjs) | Two parties meet through the in-process pipe relay: it records everything and never sees the command or output, a relay that flips one bit kills the session, and a substituted host fails the pinned host key. |
| [`10-gateway-and-address-guard.mjs`](./10-gateway-and-address-guard.mjs) | `@johnhenry/wsh/address-guard`: a name resolved once, every answer classified (loopback, private, link-local, metadata refused), and a gateway that dials a local stand-in only once a rule names it. |
| [`11-session-over-a-duplex.mjs`](./11-session-over-a-duplex.mjs) | `@johnhenry/wsh/duplex`: a sealed, host-key-bound wsh session over a plain `MessageChannel` with a 512-byte message limit; a client that names no host key, or the wrong one, is refused. |
