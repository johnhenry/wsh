//! Length-prefixed CBOR framing for the wsh control stream.
//!
//! Wire format: `[4-byte big-endian length][CBOR payload]`

use crate::error::WshResult;
use crate::messages::{Envelope, MsgType, Payload};
use std::io::Cursor;

/// Encode a serializable value into a length-prefixed CBOR frame.
///
/// The payload is canonical CBOR (RFC 8949 4.2.1, [`crate::cbor_canon`]): map keys sorted, the shortest float, definite lengths.
pub fn frame_encode<T: serde::Serialize>(value: &T) -> WshResult<Vec<u8>> {
    let payload = cbor_encode(value)?;

    let len = payload.len() as u32;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend(payload);
    Ok(frame)
}

/// Decode a CBOR payload (without length prefix) into a typed value.
///
/// Strict (#317, [`crate::cbor_strict`]): `data` must be exactly one well-formed item. A declared length past the end of the buffer, a
/// byte after the item, a non-shortest integer or length, an indefinite-length string or array, a duplicate or non-text map key, a tag, invalid UTF-8
/// and more than [`crate::cbor_strict::MAX_CONTAINERS`] arrays and maps are errors. Two legacy exceptions are on, for the compatibility window
/// (COMPATIBILITY.md rule 7): an indefinite-length map as the top-level item, and any key order, float width or NaN form (what the released encoders
/// wrote). [`cbor_decode_with`] with [`crate::cbor_strict::Options::strict`] refuses them; that becomes the default when the window closes.
pub fn cbor_decode<T: serde::de::DeserializeOwned>(data: &[u8]) -> WshResult<T> {
    cbor_decode_with(data, &crate::cbor_strict::Options::default())
}

/// [`cbor_decode`] with the legacy exceptions chosen by the caller.
pub fn cbor_decode_with<T: serde::de::DeserializeOwned>(
    data: &[u8],
    opts: &crate::cbor_strict::Options,
) -> WshResult<T> {
    crate::cbor_strict::validate_with(data, opts)
        .map_err(|e| crate::error::WshError::Codec(e.to_string()))?;
    decode_checked(data)
}

/// Deserialize bytes that [`crate::cbor_strict::validate`] has already accepted.
fn decode_checked<T: serde::de::DeserializeOwned>(data: &[u8]) -> WshResult<T> {
    let cursor = Cursor::new(data);
    let value: T = ciborium::from_reader(cursor)?;
    Ok(value)
}

/// Encode a value into a bare canonical CBOR payload (without length prefix): [`crate::cbor_canon::to_vec`].
pub fn cbor_encode<T: serde::Serialize>(value: &T) -> WshResult<Vec<u8>> {
    crate::cbor_canon::to_vec(value).map_err(|e| crate::error::WshError::Codec(e.to_string()))
}

/// Decode an envelope using the message type to disambiguate flattened payloads.
pub fn decode_envelope(data: &[u8]) -> WshResult<Envelope> {
    #[derive(serde::Deserialize)]
    struct EnvelopeTypeOnly {
        #[serde(rename = "type")]
        msg_type: MsgType,
    }

    crate::cbor_strict::validate(data).map_err(|e| crate::error::WshError::Codec(e.to_string()))?;
    let header: EnvelopeTypeOnly = decode_checked(data)?;
    let value: ciborium::value::Value = decode_checked(data)?;
    let payload_value = match value {
        ciborium::value::Value::Map(entries) => ciborium::value::Value::Map(
            entries
                .into_iter()
                .filter(
                    |(key, _)| !matches!(key, ciborium::value::Value::Text(text) if text == "type"),
                )
                .collect(),
        ),
        other => {
            return Err(crate::error::WshError::Codec(format!(
                "expected envelope map, got {:?}",
                other
            )))
        }
    };

    let mut payload_bytes = Vec::new();
    ciborium::into_writer(&payload_value, &mut payload_bytes)?;
    let payload = Payload::decode_for_msg_type(header.msg_type, &payload_bytes)?;
    Ok(Envelope {
        msg_type: header.msg_type,
        payload,
    })
}

/// Streaming frame decoder: accumulates bytes and yields complete messages.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buffer: Vec<u8>,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Feed bytes into the decoder and return all complete CBOR-decoded messages.
    ///
    /// A malformed frame fails the call and is dropped from the buffer (the frames after it are read by the next call); the good messages
    /// of the same call before it are not returned. That is deliberate: the production paths (`wsh-server`, the clients) read frames with
    /// `feed_raw` and `decode_envelope` one by one and close the session on the first error, so this typed form is for tests and
    /// single-message callers.
    pub fn feed<T: serde::de::DeserializeOwned>(&mut self, data: &[u8]) -> WshResult<Vec<T>> {
        self.buffer.extend_from_slice(data);
        let mut messages = Vec::new();

        loop {
            if self.buffer.len() < 4 {
                break;
            }
            let len = u32::from_be_bytes([
                self.buffer[0],
                self.buffer[1],
                self.buffer[2],
                self.buffer[3],
            ]) as usize;

            if self.buffer.len() < 4 + len {
                break;
            }

            let decoded = cbor_decode::<T>(&self.buffer[4..4 + len]);
            // the bad frame is consumed either way: the length prefix keeps the stream in step, and leaving it in front would fail every later call
            self.buffer.drain(..4 + len);
            messages.push(decoded?);
        }

        Ok(messages)
    }

    /// Feed raw bytes and return complete raw frames (undecoded CBOR payloads).
    pub fn feed_raw(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        self.buffer.extend_from_slice(data);
        let mut frames = Vec::new();

        loop {
            if self.buffer.len() < 4 {
                break;
            }
            let len = u32::from_be_bytes([
                self.buffer[0],
                self.buffer[1],
                self.buffer[2],
                self.buffer[3],
            ]) as usize;

            if self.buffer.len() < 4 + len {
                break;
            }

            let payload = self.buffer[4..4 + len].to_vec();
            frames.push(payload);
            self.buffer.drain(..4 + len);
        }

        frames
    }

    /// Reset internal buffer.
    pub fn reset(&mut self) {
        self.buffer.clear();
    }

    /// Number of bytes remaining in the internal buffer.
    pub fn pending(&self) -> usize {
        self.buffer.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{AuthOkPayload, ReverseListPayload};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestMsg {
        name: String,
        value: i64,
    }

    /// The bytes the JS encoder (`src/cbor.mjs`) writes at the edges of the 64-bit ranges, and what this decoder reads in them
    /// (the same vectors are asserted on the JS side in `test/cbor-hardening.test.mjs`).
    #[test]
    fn the_js_encoders_integer_and_float_boundaries_decode_to_the_same_numbers() {
        use ciborium::value::Value;
        let decode = |hex: &str| -> Value {
            ciborium::from_reader(hex::decode(hex).unwrap().as_slice()).unwrap()
        };
        let int = |v: Value| match v {
            Value::Integer(i) => i128::from(i),
            other => panic!("expected an integer, got {other:?}"),
        };
        let float = |v: Value| match v {
            Value::Float(f) => f,
            other => panic!("expected a float, got {other:?}"),
        };
        assert_eq!(int(decode("1b8000000000000000")), 1i128 << 63);
        assert_eq!(int(decode("3b7fffffffffffffff")), -(1i128 << 63));
        assert_eq!(int(decode("1bfffffffffffff800")), (1i128 << 64) - 2048);
        assert_eq!(float(decode("fb43f0000000000000")), 2f64.powi(64));
        assert_eq!(float(decode("fb444b1ae4d6e2ef50")), 1e21);
        let neg_zero = float(decode("fb8000000000000000"));
        assert!(neg_zero == 0.0 && neg_zero.is_sign_negative());
    }

    #[test]
    fn round_trip_single() {
        let msg = TestMsg {
            name: "hello".into(),
            value: 42,
        };
        let frame = frame_encode(&msg).unwrap();
        let mut decoder = FrameDecoder::new();
        let decoded: Vec<TestMsg> = decoder.feed(&frame).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0], msg);
    }

    #[test]
    fn round_trip_multiple() {
        let msgs = vec![
            TestMsg {
                name: "a".into(),
                value: 1,
            },
            TestMsg {
                name: "b".into(),
                value: 2,
            },
            TestMsg {
                name: "c".into(),
                value: 3,
            },
        ];

        let mut combined = Vec::new();
        for m in &msgs {
            combined.extend(frame_encode(m).unwrap());
        }

        let mut decoder = FrameDecoder::new();
        let decoded: Vec<TestMsg> = decoder.feed(&combined).unwrap();
        assert_eq!(decoded, msgs);
    }

    #[test]
    fn incremental_feed() {
        let msg = TestMsg {
            name: "test".into(),
            value: 99,
        };
        let frame = frame_encode(&msg).unwrap();
        let mut decoder = FrameDecoder::new();

        // Feed one byte at a time
        for i in 0..frame.len() - 1 {
            let decoded: Vec<TestMsg> = decoder.feed(&frame[i..i + 1]).unwrap();
            assert!(decoded.is_empty());
        }
        // Feed last byte
        let decoded: Vec<TestMsg> = decoder.feed(&frame[frame.len() - 1..]).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0], msg);
    }

    #[test]
    fn pending_bytes() {
        let msg = TestMsg {
            name: "x".into(),
            value: 0,
        };
        let frame = frame_encode(&msg).unwrap();
        let mut decoder = FrameDecoder::new();

        decoder.feed_raw(&frame[..3]);
        assert_eq!(decoder.pending(), 3);

        decoder.reset();
        assert_eq!(decoder.pending(), 0);
    }

    #[test]
    fn envelope_payload_decode_respects_auth_ok_variant() {
        let envelope = Envelope {
            msg_type: MsgType::AuthOk,
            payload: Payload::AuthOk(AuthOkPayload {
                session_id: "session-123".into(),
                token: vec![1, 2, 3, 4],
                ttl: 30,
            }),
        };

        let frame = frame_encode(&envelope).unwrap();
        let decoded = decode_envelope(&frame[4..]).unwrap();

        assert!(matches!(decoded.msg_type, MsgType::AuthOk));
        match decoded.payload {
            Payload::AuthOk(payload) => {
                assert_eq!(payload.session_id, "session-123");
                assert_eq!(payload.token, vec![1, 2, 3, 4]);
                assert_eq!(payload.ttl, 30);
            }
            other => panic!("expected AuthOk payload, got {:?}", other),
        }
    }

    #[test]
    fn envelope_payload_decode_respects_empty_variant() {
        let envelope = Envelope {
            msg_type: MsgType::ReverseList,
            payload: Payload::ReverseList(ReverseListPayload {}),
        };

        let frame = frame_encode(&envelope).unwrap();
        let decoded = decode_envelope(&frame[4..]).unwrap();

        assert!(matches!(decoded.msg_type, MsgType::ReverseList));
        assert!(matches!(decoded.payload, Payload::ReverseList(_)));
    }

    // wsh #89 / #90: the optional fields and the new message the JS relay and host use. The Rust relay does not act
    // on them (tracked in #93), but it must parse them, and a message without them must still parse.
    #[test]
    fn relay_forward_to_fingerprint_is_optional_both_ways() {
        use crate::messages::{Envelope, MsgType, Payload, RelayForwardPayload};
        let with = Envelope {
            msg_type: MsgType::RelayForward,
            payload: Payload::RelayForward(RelayForwardPayload {
                from_fingerprint: "peer".into(),
                inner: vec![1, 2, 3],
                to_fingerprint: Some("operator".into()),
            }),
        };
        let framed = frame_encode(&with).unwrap();
        match decode_envelope(&framed[4..]).unwrap().payload {
            Payload::RelayForward(p) => assert_eq!(p.to_fingerprint.as_deref(), Some("operator")),
            other => panic!("unexpected payload: {other:?}"),
        }
        // A forward written before the field existed (no to_fingerprint key at all) still decodes.
        let without = Envelope {
            msg_type: MsgType::RelayForward,
            payload: Payload::RelayForward(RelayForwardPayload {
                from_fingerprint: "peer".into(),
                inner: vec![],
                to_fingerprint: None,
            }),
        };
        let framed = frame_encode(&without).unwrap();
        assert!(
            !framed.windows(14).any(|w| w == b"to_fingerprint"),
            "the absent field is not on the wire"
        );
        match decode_envelope(&framed[4..]).unwrap().payload {
            Payload::RelayForward(p) => assert_eq!(p.to_fingerprint, None),
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[test]
    fn reverse_close_and_key_exchange_signature_round_trip() {
        use crate::messages::{
            Envelope, KeyExchangePayload, MsgType, Payload, ReverseClosePayload,
        };
        let close = Envelope {
            msg_type: MsgType::ReverseClose,
            payload: Payload::ReverseClose(ReverseClosePayload {
                target_fingerprint: "operator".into(),
                reason: None,
            }),
        };
        let framed = frame_encode(&close).unwrap();
        let decoded = decode_envelope(&framed[4..]).unwrap();
        assert_eq!(decoded.msg_type, MsgType::ReverseClose);
        assert!(
            matches!(decoded.payload, Payload::ReverseClose(p) if p.target_fingerprint == "operator")
        );

        let signed = Envelope {
            msg_type: MsgType::KeyExchange,
            payload: Payload::KeyExchange(KeyExchangePayload {
                algorithm: "X25519".into(),
                public_key: Some(vec![7; 32]),
                session_id: "s".into(),
                kem_public_key: None,
                kem_ciphertext: None,
                signature: Some(vec![9; 64]),
            }),
        };
        let framed = frame_encode(&signed).unwrap();
        match decode_envelope(&framed[4..]).unwrap().payload {
            Payload::KeyExchange(p) => assert_eq!(p.signature, Some(vec![9; 64])),
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    // ── strict decoding (#317) ──────────────────────────────────────────

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../spec/cbor-vectors.json")).unwrap()
    }

    #[test]
    fn cbor_decode_is_strict_a_stray_byte_a_bad_length_and_a_long_head_are_errors() {
        use ciborium::value::Value;
        assert!(cbor_decode::<Value>(&[0x00]).is_ok());
        for bad in [
            &[0x00u8, 0x00][..],
            &[0x61][..],
            &[0x18, 0x01][..],
            &[0x7a, 0, 0, 0, 0x10][..],
            &[0xf7][..],
            &[0xc0, 0x00][..],
        ] {
            assert!(cbor_decode::<Value>(bad).is_err(), "{bad:02x?}");
        }
    }

    #[test]
    fn a_frame_with_a_stray_byte_after_the_value_is_an_error_not_a_message() {
        let mut frame = frame_encode(&TestMsg {
            name: "x".into(),
            value: 1,
        })
        .unwrap();
        frame.push(0x00);
        let len = (frame.len() - 4) as u32;
        frame[..4].copy_from_slice(&len.to_be_bytes());
        let mut decoder = FrameDecoder::new();
        assert!(decoder.feed::<TestMsg>(&frame).is_err());
    }

    #[test]
    fn feed_drops_the_bad_frame_so_the_next_call_resumes_after_it() {
        // [good][bad][good] in one call: the call returns the error (the good message before it is not returned: the production
        // paths use feed_raw + decode_envelope per frame, so a bad frame there costs only itself); the bad frame is consumed, not
        // left in front of the stream forever, so the following frame is read by the next call.
        let good = |n: i64| {
            frame_encode(&TestMsg {
                name: "m".into(),
                value: n,
            })
            .unwrap()
        };
        let mut bad = good(0);
        bad.push(0x00);
        let len = (bad.len() - 4) as u32;
        bad[..4].copy_from_slice(&len.to_be_bytes());
        let mut chunk = good(1);
        chunk.extend(&bad);
        chunk.extend(good(2));
        let mut decoder = FrameDecoder::new();
        assert!(decoder.feed::<TestMsg>(&chunk).is_err());
        let rest: Vec<TestMsg> = decoder.feed(&[]).unwrap();
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].value, 2);
        assert_eq!(decoder.pending(), 0);
    }

    #[test]
    fn an_encoded_envelope_is_a_definite_length_map_not_serdes_indefinite_flatten_map() {
        let v = vectors();
        let mut n = 0;
        for vec in v["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|x| x["layer"] == "control")
        {
            let js = hex::decode(vec["js"].as_str().unwrap()).unwrap();
            let env = decode_envelope(&js).unwrap();
            let out = cbor_encode(&env).unwrap();
            assert_ne!(out[0], 0xbf, "{}: indefinite-length map", vec["name"]);
            assert_eq!(out[0] >> 5, 5, "{}: a map", vec["name"]);
            crate::cbor_strict::validate_with(
                &out,
                &crate::cbor_strict::Options {
                    legacy_indefinite_map: false,
                    legacy_non_canonical: false,
                },
            )
            .unwrap_or_else(|e| panic!("{}: {e}", vec["name"]));
            // and what it says is unchanged
            let back = decode_envelope(&out).unwrap();
            assert_eq!(back.msg_type, env.msg_type);
            n += 1;
        }
        assert!(n >= 200, "{n}");
    }

    #[test]
    fn decode_envelope_is_strict_a_stray_byte_a_long_head_and_a_cut_frame_are_errors() {
        let v = vectors();
        let ping = v["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["name"] == "Ping" && x["kind"] == "min")
            .unwrap();
        let good = ping["js"].as_str().unwrap().to_string();
        assert!(
            decode_envelope(&hex::decode(&good).unwrap()).is_ok(),
            "{good}"
        );
        // a byte after the envelope
        assert!(decode_envelope(&hex::decode(format!("{good}00")).unwrap()).is_err());
        // the type (0x21) in the four-byte form instead of the shortest one
        let longer = good.replacen("1821", "1a00000021", 1);
        assert_ne!(longer, good, "the vector holds type 0x21 as 18 21");
        assert!(decode_envelope(&hex::decode(longer).unwrap()).is_err());
        // cut one byte short
        assert!(decode_envelope(&hex::decode(&good[..good.len() - 2]).unwrap()).is_err());
        // the same malformed bytes in an indefinite-length envelope (the legacy shape)
        let legacy = format!("bf{}ff", &good[2..]);
        assert!(
            decode_envelope(&hex::decode(&legacy).unwrap()).is_ok(),
            "the legacy shape of the same message"
        );
        assert!(
            decode_envelope(&hex::decode(legacy.replacen("1821", "1a00000021", 1)).unwrap())
                .is_err()
        );
    }

    #[test]
    fn a_released_rust_peers_indefinite_map_envelope_is_still_read() {
        let v = vectors();
        for vec in v["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|x| x["layer"] == "control")
        {
            let old = hex::decode(vec["rust_released"].as_str().unwrap()).unwrap();
            assert_eq!(old[0], 0xbf);
            let env = decode_envelope(&old).unwrap_or_else(|e| panic!("{}: {e}", vec["name"]));
            assert_eq!(env.msg_type as u8 as u64, vec["code"].as_u64().unwrap());
        }
    }

    /// What the JS encoder writes for an integral value in an `f64` field is an integer item (#335): `cpu: 1`, `confidence: 1`, `load: 0`.
    #[test]
    fn an_integer_item_in_an_f64_field_is_read() {
        use crate::messages::Payload;
        let metrics = decode_envelope(&hex::decode("a2636370750164747970651838").unwrap()).unwrap();
        assert!(matches!(metrics.payload, Payload::Metrics(ref m) if m.cpu == Some(1.0)));
        let suggest = decode_envelope(
            &hex::decode("a46474797065188c6a636f6e666964656e6365016a73657373696f6e5f696461736a73756767657374696f6e6178").unwrap(),
        )
        .unwrap();
        assert!(
            matches!(suggest.payload, Payload::CopilotSuggest(ref c) if c.confidence == Some(1.0))
        );
        let announce = decode_envelope(
            &hex::decode("a5646c6f61640064747970651894676e6f64655f6964616e6863617061636974790168656e64706f696e746165").unwrap(),
        )
        .unwrap();
        assert!(matches!(announce.payload, Payload::NodeAnnounce(ref n) if n.load == 0.0));
        // a float in an integer field is still refused
        assert!(decode_envelope(&hex::decode("a263637075f93c0064747970651838").unwrap()).is_ok());
        assert!(
            decode_envelope(&hex::decode("a2666d656d6f7279f93c0064747970651838").unwrap()).is_err()
        );
    }
}
