//! Length-prefixed CBOR framing for the wsh control stream.
//!
//! Wire format: `[4-byte big-endian length][CBOR payload]`

use crate::error::WshResult;
use crate::messages::{Envelope, MsgType, Payload};
use std::io::Cursor;

/// Encode a serializable value into a length-prefixed CBOR frame.
pub fn frame_encode<T: serde::Serialize>(value: &T) -> WshResult<Vec<u8>> {
    let mut payload = Vec::new();
    ciborium::into_writer(value, &mut payload)?;

    let len = payload.len() as u32;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend(payload);
    Ok(frame)
}

/// Decode a CBOR payload (without length prefix) into a typed value.
pub fn cbor_decode<T: serde::de::DeserializeOwned>(data: &[u8]) -> WshResult<T> {
    let cursor = Cursor::new(data);
    let value: T = ciborium::from_reader(cursor)?;
    Ok(value)
}

/// Decode an envelope using the message type to disambiguate flattened payloads.
pub fn decode_envelope(data: &[u8]) -> WshResult<Envelope> {
    #[derive(serde::Deserialize)]
    struct EnvelopeTypeOnly {
        #[serde(rename = "type")]
        msg_type: MsgType,
    }

    let header: EnvelopeTypeOnly = cbor_decode(data)?;
    let value: ciborium::value::Value = cbor_decode(data)?;
    let payload_value = match value {
        ciborium::value::Value::Map(entries) => ciborium::value::Value::Map(
            entries
                .into_iter()
                .filter(|(key, _)| !matches!(key, ciborium::value::Value::Text(text) if text == "type"))
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

            let payload = &self.buffer[4..4 + len];
            let msg: T = cbor_decode(payload)?;
            messages.push(msg);

            self.buffer.drain(..4 + len);
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
}
