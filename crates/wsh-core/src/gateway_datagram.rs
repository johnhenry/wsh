//! UDP flows as WebTransport datagrams (`gateway-datagram`, wsh #124): the feature string and the
//! datagram layout, the same as the JS implementation (`src/gateway-datagram.mjs`).
//!
//! Negotiation: the client lists [`GATEWAY_DATAGRAM_FEATURE`] in `Hello.features` when its transport
//! has datagrams (WebTransport only); the host lists it in `ServerHello.features` when its transport
//! has them and its gateway serves UDP. Both listed means every `OpenUdp` flow of that connection
//! carries its payloads as datagrams instead of `GatewayData` on the control stream. `OpenUdp`,
//! `GatewayOk`/`GatewayFail` and `GatewayClose` always stay on the control stream.
//!
//! A datagram is the whole QUIC datagram payload, one UDP payload per datagram:
//!
//! ```text
//!  0       1       2       3       4 ...
//! +-------+-------+-------+-------+--------------------------+
//! |  gateway_id (u32, big endian) |  UDP payload (0..n bytes) |
//! +-------+-------+-------+-------+--------------------------+
//! ```
//!
//! `gateway_id` is the id the client chose in `OpenUdp`. A datagram naming a flow the receiver does
//! not have is dropped. Nothing is metered by `GatewayCredit` on a datagram flow (datagrams are
//! dropped, never queued). A payload that does not fit `max_datagram_size - 4` travels as
//! `GatewayData` on the control stream instead, unless the receiver is configured to drop it.

/// Feature string: "UDP flows may use WebTransport datagrams".
pub const GATEWAY_DATAGRAM_FEATURE: &str = "gateway-datagram";
/// Bytes of the flow-id header in front of each UDP payload.
pub const DATAGRAM_HEADER_BYTES: usize = 4;
/// The largest UDP payload a flow carries (an IPv4 datagram's limit).
pub const MAX_UDP_PAYLOAD: usize = 65_507;

/// `[gateway_id u32 BE][payload]`.
pub fn encode_datagram(id: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(DATAGRAM_HEADER_BYTES + payload.len());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// The flow id and the payload, or `None` when `bytes` is too short to be a datagram.
pub fn decode_datagram(bytes: &[u8]) -> Option<(u32, &[u8])> {
    if bytes.len() < DATAGRAM_HEADER_BYTES {
        return None;
    }
    let id = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    Some((id, &bytes[DATAGRAM_HEADER_BYTES..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_datagram_is_a_4_byte_big_endian_flow_id_and_then_the_payload() {
        // The same vector as test/gateway-datagram.test.mjs.
        let d = encode_datagram(0x4000_0001, &[1, 2, 3]);
        assert_eq!(d, vec![0x40, 0, 0, 1, 1, 2, 3]);
        assert_eq!(DATAGRAM_HEADER_BYTES, 4);
        assert_eq!(decode_datagram(&d), Some((0x4000_0001, &[1u8, 2, 3][..])));
    }

    #[test]
    fn an_empty_payload_is_a_valid_datagram_and_a_short_one_is_not() {
        let d = encode_datagram(7, &[]);
        assert_eq!(decode_datagram(&d), Some((7, &[][..])));
        assert_eq!(decode_datagram(&[1, 2, 3]), None);
        assert_eq!(decode_datagram(&[]), None);
    }

    #[test]
    fn the_largest_flow_id_and_payload_round_trip() {
        let payload = vec![9u8; MAX_UDP_PAYLOAD];
        let d = encode_datagram(u32::MAX, &payload);
        assert_eq!(d.len(), MAX_UDP_PAYLOAD + 4);
        let (id, back) = decode_datagram(&d).unwrap();
        assert_eq!(id, u32::MAX);
        assert_eq!(back, &payload[..]);
    }
}
