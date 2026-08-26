# wsh examples

Small, self-contained, runnable demonstrations of wsh behavior. Every example runs headless under plain Node (>= 24, for WebCrypto Ed25519) with no network, no server, and no dependencies — protocol peers are simulated in-process, exchanging the same wire bytes a real transport would carry.

Run one with `npm run example:01` (etc.), or all of them with `npm run examples`.

| Example | Demonstrates |
|---|---|
| [`01-frames-survive-fragmented-transport.mjs`](./01-frames-survive-fragmented-transport.mjs) | Length-prefixed CBOR frames reassemble intact no matter how the byte stream is fragmented in transit. |
| [`02-tampered-challenge-fails-authentication.mjs`](./02-tampered-challenge-fails-authentication.mjs) | Ed25519 challenge-response: the transcript binds signatures to session + nonce, so replays, forged nonces, and impostor keys are all rejected. |
| [`03-handshake-to-exec-over-in-process-pipe.mjs`](./03-handshake-to-exec-over-in-process-pipe.mjs) | A full HELLO → CHALLENGE → AUTH → OPEN(exec) → SESSION_DATA → EXIT conversation in wire format, with pre-auth channel opens refused. |
| [`04-recording-replays-with-original-timing.mjs`](./04-recording-replays-with-original-timing.mjs) | Session recording round-trips through asciicast-v2-compatible JSON and replays with inter-event timing preserved. |
| [`05-remote-mcp-tools-called-through-bridge.mjs`](./05-remote-mcp-tools-called-through-bridge.mjs) | MCP tools on a remote host are discovered and invoked over the control channel, with undiscovered tools rejected client-side. |
