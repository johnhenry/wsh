//! Phase 2 (#38) feasibility spike: WISP reverse-connect stream demultiplexing.
//!
//! **This is a design proof-of-concept only. It is not wired into the live
//! relay** (`broker.rs` / `registry.rs` / `server.rs` are untouched). It
//! exists to prove that the demultiplexing logic a real implementation would
//! need is sound, using synthetic input, per the #38 Phase 2 spike mandate.
//!
//! ## Background
//!
//! [WISP](https://github.com/MercuryWorkshop/wisp-protocol) frames used by
//! v86's `wisp://`/`wisps://` net backend (and mirrored client-side in
//! `web/clawser-wisp.mjs`) look like:
//!
//! ```text
//! [type:u8][stream_id:u32 LE][payload...]
//! ```
//!
//! with base opcodes `0x01 CONNECT`, `0x02 DATA`, `0x03 CONTINUE`,
//! `0x04 CLOSE` (`0x05` is reserved by WISP v2 for `PROTOEXT`/upgrade
//! negotiation, which v86's shipped client already no-ops on receipt — see
//! `src/browser/wisp_network.js` upstream, `case 5: ... "ignoring"`).
//!
//! CONNECT is defined as strictly client(guest)-initiated by the WISP spec
//! itself (confirmed directly against upstream `protocol.md`: "The client
//! needs to send a CONNECT packet to the server..." — no server-initiated
//! opcode exists). v86's own `WispNetworkAdapter.process_incoming_wisp_frame`
//! (`src/browser/wisp_network.js`) enforces this at the implementation level
//! too: an unsolicited `DATA` frame for a `stream_id` the guest never
//! CONNECTed **throws** (`"Got a DATA packet but stream not registered"`),
//! and an incoming `CONNECT` from the relay is a hard no-op
//! (`"Server sent client-only packet CONNECT"`). So a same-wire-format hack
//! that just sends DATA on an unopened stream_id does not work — this was
//! verified by reading the actual shipped v86 source, not assumed.
//!
//! However, v86's `fake_network.js` already contains the primitive needed to
//! synthesize an inbound connection *into* the guest:
//! `fake_tcp_connect(dport, adapter)` fabricates a real SYN packet from the
//! router toward the guest's TCP stack and returns a `TCPConnection` handle
//! with `data`/`close` event hooks. It is proven, shipping code — currently
//! wired up only by `fetch_network.js` (the `fetch://` backend uses it to let
//! the browser tab open a connection to a server running inside the guest),
//! *not* by `wisp_network.js`.
//!
//! So the buildable extension is narrow: add **one new opcode**,
//! `REVERSE_OPEN` (relay→guest only), that a patched `wisp_network.js` turns
//! into `fake_tcp_connect(local_port, this)`, registering the resulting
//! `TCPConnection`'s callbacks against a stream_id chosen by the *relay*
//! rather than the guest's own `last_stream` counter. Every other opcode
//! (`DATA`/`CONTINUE`/`CLOSE`) is reused completely unmodified in both
//! directions once the stream exists — v86's adapter only cares that
//! `this.connections[stream_id]` exists, not who created it.
//!
//! This module proves the relay-side half of that: allocating reverse
//! stream_ids from a range that can never collide with the guest's own
//! outbound allocation, and demultiplexing frames arriving on the guest's one
//! shared WebSocket back to the correct logical bridge (an existing
//! guest-initiated outbound tunnel vs. a relay-initiated reverse tunnel).
//!
//! ## What this does NOT prove
//!
//! - It does not touch v86 itself. The `REVERSE_OPEN` → `fake_tcp_connect`
//!   wiring described above requires patching (forking) v86's
//!   `wisp_network.js`, since `web/clawser-v86-guest.mjs` currently loads
//!   stock v86 from jsdelivr's CDN unmodified. That's real, separate,
//!   non-trivial work (build + host a patched v86 bundle) that this spike
//!   deliberately does not attempt.
//! - It does not implement the relay's WISP-speaking endpoint itself.
//!   `crates/wsh-server/src/relay/` today only implements wsh's own bespoke
//!   Envelope-based `ReverseConnect` protocol (see `registry.rs`/`broker.rs`/
//!   `server.rs`), which is architecturally analogous but a completely
//!   different wire format from WISP — no WISP framing exists anywhere in
//!   this Rust codebase yet (confirmed: no `wisp` crate dependency, no WISP
//!   encode/decode in Rust; the only WISP implementation in this repo is the
//!   *client*-side JS in `web/clawser-wisp.mjs`/`clawser-wisp-transport.mjs`).

use std::collections::HashSet;

/// Base WISP opcodes (unchanged from upstream WISP v1 / v86's client).
pub const WISP_CONNECT: u8 = 0x01;
pub const WISP_DATA: u8 = 0x02;
pub const WISP_CONTINUE: u8 = 0x03;
pub const WISP_CLOSE: u8 = 0x04;

/// New opcode this spike proposes: relay → guest only. Payload is the
/// guest-local TCP port to synthesize an inbound connection to
/// (`local_port: u16 LE`). Chosen outside the WISP v1 base range (1-4) and
/// distinct from the WISP v2-reserved `0x05 PROTOEXT` to avoid ever
/// colliding with a real WISP v2 upgrade if this codebase adopts one later.
pub const WISP_REVERSE_OPEN: u8 = 0x10;

/// Stream IDs below this are guest-initiated (outbound), allocated by the
/// guest's own v86 `wisp_network.js`, whose `last_stream` counter starts at
/// 1 and increments by 1 per guest CONNECT. IDs at/above this are
/// relay-initiated (reverse/inbound), allocated by wsh-server's relay.
/// Splitting the u32 space in half guarantees no collision with zero
/// coordination handshake — no real guest will ever open 2^31 outbound
/// streams — while keeping both families of stream_id in the same flat
/// namespace the wire format already uses.
pub const REVERSE_STREAM_ID_BASE: u32 = 0x8000_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamDirection {
    /// Guest dialed out; relay is the WISP "server" side, exactly as today.
    GuestOutbound,
    /// Relay synthesized this on behalf of an external `wsh connect
    /// <guest-fingerprint>`; a patched guest-side `wisp_network.js` turned it
    /// into a fake inbound SYN via `fake_tcp_connect()`.
    RelayReverse,
}

pub fn classify_stream(stream_id: u32) -> StreamDirection {
    if stream_id >= REVERSE_STREAM_ID_BASE {
        StreamDirection::RelayReverse
    } else {
        StreamDirection::GuestOutbound
    }
}

/// Allocates stream IDs for relay-initiated reverse connections, wrapping
/// within the upper half of the u32 space.
pub struct ReverseStreamAllocator {
    next: u32,
}

impl Default for ReverseStreamAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl ReverseStreamAllocator {
    pub fn new() -> Self {
        Self {
            next: REVERSE_STREAM_ID_BASE,
        }
    }

    pub fn allocate(&mut self) -> u32 {
        let id = self.next;
        self.next = if self.next == u32::MAX {
            REVERSE_STREAM_ID_BASE
        } else {
            self.next + 1
        };
        id
    }
}

/// A frame as read off the guest's single outbound WISP WebSocket by the relay.
pub struct WispFrame {
    pub frame_type: u8,
    pub stream_id: u32,
    pub payload: Vec<u8>,
}

pub fn decode_frame(bytes: &[u8]) -> Option<WispFrame> {
    if bytes.len() < 5 {
        return None;
    }
    let frame_type = bytes[0];
    let stream_id = u32::from_le_bytes(bytes[1..5].try_into().ok()?);
    Some(WispFrame {
        frame_type,
        stream_id,
        payload: bytes[5..].to_vec(),
    })
}

pub fn encode_reverse_open(stream_id: u32, local_port: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(7);
    buf.push(WISP_REVERSE_OPEN);
    buf.extend_from_slice(&stream_id.to_le_bytes());
    buf.extend_from_slice(&local_port.to_le_bytes());
    buf
}

/// Where an incoming DATA/CONTINUE/CLOSE frame from the guest's WebSocket
/// should be routed. `Unknown` frames (unregistered stream_id) must be
/// dropped, never guessed at — mirrors v86's own client-side behavior of
/// refusing frames for streams it didn't create.
#[derive(Debug, PartialEq, Eq)]
pub enum RouteTarget {
    /// Bridges to the external target the *guest* originally CONNECTed to
    /// (today's stock WISP relay behavior, unmodified by this proposal).
    OutboundBridge(u32),
    /// Bridges to the external `wsh connect` client whose request triggered
    /// the `REVERSE_OPEN` for this stream_id (the new path).
    ReverseBridge(u32),
    Unknown,
}

pub fn route_frame(
    frame: &WispFrame,
    known_outbound: &HashSet<u32>,
    known_reverse: &HashSet<u32>,
) -> RouteTarget {
    match classify_stream(frame.stream_id) {
        StreamDirection::GuestOutbound if known_outbound.contains(&frame.stream_id) => {
            RouteTarget::OutboundBridge(frame.stream_id)
        }
        StreamDirection::RelayReverse if known_reverse.contains(&frame.stream_id) => {
            RouteTarget::ReverseBridge(frame.stream_id)
        }
        _ => RouteTarget::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_and_outbound_ids_never_collide() {
        let mut alloc = ReverseStreamAllocator::new();
        let r1 = alloc.allocate();
        let r2 = alloc.allocate();
        assert_ne!(r1, r2);
        assert_eq!(classify_stream(r1), StreamDirection::RelayReverse);
        assert_eq!(classify_stream(1), StreamDirection::GuestOutbound);
        assert_eq!(
            classify_stream(REVERSE_STREAM_ID_BASE - 1),
            StreamDirection::GuestOutbound
        );
        assert_eq!(
            classify_stream(REVERSE_STREAM_ID_BASE),
            StreamDirection::RelayReverse
        );
    }

    #[test]
    fn demuxes_data_frames_by_origin_without_guessing() {
        let mut alloc = ReverseStreamAllocator::new();
        let reverse_id = alloc.allocate();
        let outbound_id = 42u32;

        let mut known_outbound = HashSet::new();
        known_outbound.insert(outbound_id);
        let mut known_reverse = HashSet::new();
        known_reverse.insert(reverse_id);

        // Synthetic DATA frame the guest sent on its own outbound stream
        // (e.g. it dialed out to some internet host — stock WISP behavior).
        let mut raw = vec![WISP_DATA];
        raw.extend_from_slice(&outbound_id.to_le_bytes());
        raw.extend_from_slice(b"hello outbound");
        let frame = decode_frame(&raw).unwrap();
        assert_eq!(
            route_frame(&frame, &known_outbound, &known_reverse),
            RouteTarget::OutboundBridge(outbound_id)
        );

        // Synthetic DATA frame the guest's patched adapter sent back on the
        // relay-opened reverse stream (i.e. wsh-server inside the guest
        // replying to an external `wsh connect <guest-fp>` client).
        let mut raw2 = vec![WISP_DATA];
        raw2.extend_from_slice(&reverse_id.to_le_bytes());
        raw2.extend_from_slice(b"hello reverse");
        let frame2 = decode_frame(&raw2).unwrap();
        assert_eq!(
            route_frame(&frame2, &known_outbound, &known_reverse),
            RouteTarget::ReverseBridge(reverse_id)
        );

        // A frame on a stream_id nobody registered must not be silently
        // routed anywhere — this is the same fail-closed behavior v86's own
        // client enforces today (it throws rather than guessing).
        let mut raw3 = vec![WISP_DATA];
        raw3.extend_from_slice(&999u32.to_le_bytes());
        let frame3 = decode_frame(&raw3).unwrap();
        assert_eq!(
            route_frame(&frame3, &known_outbound, &known_reverse),
            RouteTarget::Unknown
        );
    }

    #[test]
    fn reverse_open_frame_encodes_target_port_after_stream_id() {
        let frame = encode_reverse_open(REVERSE_STREAM_ID_BASE, 9999);
        assert_eq!(frame[0], WISP_REVERSE_OPEN);
        let stream_id = u32::from_le_bytes(frame[1..5].try_into().unwrap());
        assert_eq!(stream_id, REVERSE_STREAM_ID_BASE);
        let port = u16::from_le_bytes(frame[5..7].try_into().unwrap());
        assert_eq!(port, 9999);
    }

    #[test]
    fn base_opcodes_are_unchanged_from_upstream_wisp() {
        // Sanity check against the frame format documented in
        // web/clawser-wisp.mjs and v86's wisp_network.js, so this proposal's
        // new opcode can never be confused with an existing one.
        assert_eq!(WISP_CONNECT, 0x01);
        assert_eq!(WISP_DATA, 0x02);
        assert_eq!(WISP_CONTINUE, 0x03);
        assert_eq!(WISP_CLOSE, 0x04);
        assert_eq!(WISP_REVERSE_OPEN, 0x10);
    }
}
