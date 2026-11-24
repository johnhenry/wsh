//! The data stream of a typed `rpc` channel (wsh #85) as a client reads and writes it: a CBOR sequence
//! (RFC 8742) of JSON-RPC 2.0 messages, with the items seen as `serde_json::Value`.
//!
//! The same framing `wsh-server` decodes for the channels it hosts (`wsh-server/src/rpc/seq.rs`) and
//! `CborSequenceDecoder` in `src/rpc.mjs` decodes in JS: one data item after another, self-delimiting,
//! no length prefix; an item over the bound is refused as soon as it is detectable; malformed CBOR
//! (reserved additional information, an unexpected break, indefinite integers, nesting past 128) is an
//! error. This is the bound that matters to a client: a host cannot make it buffer more than `max`
//! bytes towards one item.

pub use ciborium::value::Value as Cbor;
use serde_json::Value as Json;

/// JSON-RPC's parse error, which a malformed stream is reported as.
pub const PARSE: i64 = -32700;
/// JSON-RPC's invalid request, which an item over the bound is reported as.
pub const INVALID_REQUEST: i64 = -32600;

/// A stream that cannot be decoded (the channel is not usable after it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcCodecError {
    /// [`PARSE`] for malformed CBOR, [`INVALID_REQUEST`] for an item over the bound.
    pub code: i64,
    pub message: String,
}

impl std::fmt::Display for RpcCodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.message, self.code)
    }
}

impl std::error::Error for RpcCodecError {}

const MAX_DEPTH: usize = 128;

enum Scan {
    Incomplete,
    Bad(RpcCodecError),
}

impl From<RpcCodecError> for Scan {
    fn from(e: RpcCodecError) -> Self {
        Scan::Bad(e)
    }
}

fn parse_err(msg: &str) -> Scan {
    Scan::Bad(RpcCodecError {
        code: PARSE,
        message: msg.to_string(),
    })
}

fn too_large(size: usize, max: usize) -> RpcCodecError {
    RpcCodecError {
        code: INVALID_REQUEST,
        message: format!("message of {size} bytes exceeds the {max} byte rpc message limit"),
    }
}

/// End offset of the CBOR data item starting at `off`, or `Incomplete` if `buf` ends first.
fn scan(buf: &[u8], mut off: usize, max: usize, depth: usize) -> Result<usize, Scan> {
    if depth > MAX_DEPTH {
        return Err(parse_err("cbor nesting too deep"));
    }
    if off >= buf.len() {
        return Err(Scan::Incomplete);
    }
    let initial = buf[off];
    off += 1;
    let mt = initial >> 5;
    let ai = initial & 0x1f;
    if (28..=30).contains(&ai) {
        return Err(parse_err("malformed cbor (reserved additional info)"));
    }
    let indefinite = ai == 31;
    let mut arg: u64 = 0;
    if ai < 24 {
        arg = ai as u64;
    } else if ai <= 27 {
        let n = match ai {
            24 => 1,
            25 => 2,
            26 => 4,
            _ => 8,
        };
        if off + n > buf.len() {
            return Err(Scan::Incomplete);
        }
        for i in 0..n {
            arg = arg.wrapping_mul(256).wrapping_add(buf[off + i] as u64);
        }
        off += n;
    }
    let too_big = |a: u64| a > max as u64;
    match mt {
        0 | 1 => {
            if indefinite {
                return Err(parse_err("malformed cbor (indefinite integer)"));
            }
            Ok(off)
        }
        2 | 3 => {
            if indefinite {
                loop {
                    if off >= buf.len() {
                        return Err(Scan::Incomplete);
                    }
                    if buf[off] == 0xff {
                        return Ok(off + 1);
                    }
                    if (buf[off] >> 5) != mt || (buf[off] & 0x1f) == 31 {
                        return Err(parse_err("malformed cbor (bad string chunk)"));
                    }
                    off = scan(buf, off, max, depth + 1)?;
                }
            }
            if too_big(arg) {
                return Err(too_large(arg.min(usize::MAX as u64) as usize, max).into());
            }
            let arg = arg as usize;
            if off + arg > buf.len() {
                return Err(Scan::Incomplete);
            }
            Ok(off + arg)
        }
        4 | 5 => {
            let per = if mt == 5 { 2 } else { 1 };
            if indefinite {
                loop {
                    if off >= buf.len() {
                        return Err(Scan::Incomplete);
                    }
                    if buf[off] == 0xff {
                        return Ok(off + 1);
                    }
                    for _ in 0..per {
                        off = scan(buf, off, max, depth + 1)?;
                    }
                }
            }
            if too_big(arg) {
                // every element is at least a byte
                return Err(too_large(arg.min(usize::MAX as u64) as usize, max).into());
            }
            for _ in 0..(arg as usize * per) {
                off = scan(buf, off, max, depth + 1)?;
            }
            Ok(off)
        }
        6 => {
            if indefinite {
                return Err(parse_err("malformed cbor (indefinite tag)"));
            }
            scan(buf, off, max, depth + 1)
        }
        // 7: simple values and floats; 0xff outside an indefinite item is invalid
        _ => {
            if indefinite {
                return Err(parse_err("malformed cbor (unexpected break)"));
            }
            Ok(off)
        }
    }
}

/// Incremental decoder: `feed()` bytes as they arrive, get back every message completed so far.
#[derive(Debug)]
pub struct CborSequenceDecoder {
    buf: Vec<u8>,
    max: usize,
}

impl CborSequenceDecoder {
    /// `max_item_bytes`: the largest single message accepted (the host's `rpc-max-message:<n>`).
    pub fn new(max_item_bytes: usize) -> Self {
        Self {
            buf: Vec::new(),
            max: max_item_bytes,
        }
    }

    /// Bytes buffered towards an incomplete item.
    pub fn pending(&self) -> usize {
        self.buf.len()
    }

    /// Feed bytes; returns every message completed so far as JSON (a byte string is an error: JSON has none).
    /// On error the buffer is dropped.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<Json>, RpcCodecError> {
        self.feed_values(chunk)?
            .into_iter()
            .map(to_json)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                self.buf.clear();
                e
            })
    }

    /// Like [`feed`](Self::feed), but the messages are CBOR values as they are: a byte string stays a byte string
    /// (the `wsh-objects` protocol carries bytes natively). The same bounds hold.
    pub fn feed_values(&mut self, chunk: &[u8]) -> Result<Vec<Cbor>, RpcCodecError> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        let mut off = 0usize;
        let result = (|| -> Result<(), RpcCodecError> {
            while off < self.buf.len() {
                let end = match scan(&self.buf, off, self.max, 0) {
                    Ok(end) => end,
                    Err(Scan::Incomplete) => {
                        if self.buf.len() - off > self.max {
                            return Err(too_large(self.buf.len() - off, self.max));
                        }
                        break;
                    }
                    Err(Scan::Bad(e)) => return Err(e),
                };
                if end - off > self.max {
                    return Err(too_large(end - off, self.max));
                }
                let item: Cbor =
                    ciborium::from_reader(&self.buf[off..end]).map_err(|e| RpcCodecError {
                        code: PARSE,
                        message: format!("malformed cbor: {e}"),
                    })?;
                out.push(item);
                off = end;
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.buf.drain(..off);
                Ok(out)
            }
            Err(e) => {
                self.buf.clear();
                Err(e)
            }
        }
    }
}

/// One message as the CBOR data item that goes on the stream.
pub fn encode_message(message: &Json) -> Result<Vec<u8>, RpcCodecError> {
    let mut out = Vec::new();
    ciborium::into_writer(message, &mut out).map_err(|e| RpcCodecError {
        code: PARSE,
        message: format!("cannot encode the message: {e}"),
    })?;
    Ok(out)
}

/// One CBOR value as the data item that goes on the stream.
pub fn encode_cbor(message: &Cbor) -> Result<Vec<u8>, RpcCodecError> {
    let mut out = Vec::new();
    ciborium::into_writer(message, &mut out).map_err(|e| RpcCodecError {
        code: PARSE,
        message: format!("cannot encode the message: {e}"),
    })?;
    Ok(out)
}

/// A decoded message as JSON; a byte string, and a map key that is not text, cannot be.
pub fn to_json(v: Cbor) -> Result<Json, RpcCodecError> {
    Ok(match v {
        Cbor::Null => Json::Null,
        Cbor::Bool(b) => Json::Bool(b),
        Cbor::Integer(i) => {
            let n = i128::from(i);
            if let Ok(u) = u64::try_from(n) {
                Json::from(u)
            } else if let Ok(s) = i64::try_from(n) {
                Json::from(s)
            } else {
                serde_json::Number::from_f64(n as f64).map_or(Json::Null, Json::Number)
            }
        }
        // JSON has no NaN or infinity: JavaScript's JSON.stringify turns them into null too.
        Cbor::Float(f) => serde_json::Number::from_f64(f).map_or(Json::Null, Json::Number),
        Cbor::Text(s) => Json::String(s),
        Cbor::Array(items) => Json::Array(
            items
                .into_iter()
                .map(to_json)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Cbor::Map(entries) => {
            let mut map = serde_json::Map::new();
            for (k, v) in entries {
                let Cbor::Text(key) = k else {
                    return Err(RpcCodecError {
                        code: PARSE,
                        message: "a map key that is not text cannot be a JSON member name".into(),
                    });
                };
                map.insert(key, to_json(v)?);
            }
            Json::Object(map)
        }
        Cbor::Tag(_, inner) => to_json(*inner)?,
        Cbor::Bytes(_) => {
            return Err(RpcCodecError {
                code: PARSE,
                message: "a byte string cannot be carried as JSON".into(),
            })
        }
        _ => {
            return Err(RpcCodecError {
                code: PARSE,
                message: "unsupported cbor value".into(),
            })
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_message_round_trips_split_at_every_byte() {
        let a = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {"cursor": null, "n": [1, 2.5, "x", true]}});
        let b = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        let mut bytes = encode_message(&a).unwrap();
        bytes.extend(encode_message(&b).unwrap());
        let mut d = CborSequenceDecoder::new(4096);
        let mut got = Vec::new();
        for byte in &bytes {
            got.extend(d.feed(&[*byte]).unwrap());
        }
        assert_eq!(got, vec![a, b]);
        assert_eq!(d.pending(), 0);
    }

    #[test]
    fn an_oversized_item_is_refused_when_its_header_is_seen() {
        let mut d = CborSequenceDecoder::new(100);
        // a text string of 1000 bytes: only the 3-byte header arrives
        let e = d.feed(&[0x79, 0x03, 0xe8]).unwrap_err();
        assert_eq!(e.code, INVALID_REQUEST);
        assert!(e.message.contains("exceeds the 100 byte rpc message limit"));
        assert_eq!(d.pending(), 0);
    }

    #[test]
    fn an_endless_item_is_refused_at_the_bound() {
        let mut d = CborSequenceDecoder::new(10);
        let mut bytes = vec![0x9f];
        bytes.extend(std::iter::repeat(0x01).take(20));
        assert_eq!(d.feed(&bytes).unwrap_err().code, INVALID_REQUEST);
    }

    #[test]
    fn malformed_cbor_is_a_parse_error() {
        for bad in [&[0x1c][..], &[0xff][..], &[0x1f][..], &[0xdf, 0x01][..]] {
            let mut d = CborSequenceDecoder::new(64);
            assert_eq!(d.feed(bad).unwrap_err().code, PARSE, "{bad:?}");
        }
    }

    #[test]
    fn deep_nesting_is_refused() {
        let mut d = CborSequenceDecoder::new(4096);
        assert_eq!(d.feed(&vec![0x81; 300]).unwrap_err().code, PARSE);
    }

    #[test]
    fn a_byte_string_is_refused_not_guessed_at() {
        let mut d = CborSequenceDecoder::new(64);
        assert_eq!(d.feed(&[0x41, 0x07]).unwrap_err().code, PARSE);
    }

    #[test]
    fn values_keep_a_byte_string_that_json_cannot() {
        let mut d = CborSequenceDecoder::new(64);
        // h'0107', then a map {"b": h'ff'}
        let items = d
            .feed_values(&[0x42, 0x01, 0x07, 0xa1, 0x61, b'b', 0x41, 0xff])
            .unwrap();
        assert_eq!(items[0], Cbor::Bytes(vec![1, 7]));
        assert_eq!(
            items[1],
            Cbor::Map(vec![(Cbor::Text("b".into()), Cbor::Bytes(vec![0xff]))])
        );
        assert_eq!(
            encode_cbor(&items[0]).unwrap(),
            vec![0x42, 0x01, 0x07],
            "and it goes back as it came"
        );
        // the bound holds all the same
        let mut small = CborSequenceDecoder::new(4);
        assert_eq!(
            small.feed_values(&[0x45, 1, 2, 3, 4, 5]).unwrap_err().code,
            INVALID_REQUEST
        );
    }

    #[test]
    fn indefinite_strings_and_maps_decode() {
        let mut d = CborSequenceDecoder::new(64);
        let items = d
            .feed(&[
                0x7f, 0x61, b'a', 0x61, b'b', 0xff, 0xbf, 0x61, b'k', 0x01, 0xff,
            ])
            .unwrap();
        assert_eq!(items, vec![json!("ab"), json!({"k": 1})]);
    }

    #[test]
    fn integers_keep_their_sign_and_size() {
        let mut d = CborSequenceDecoder::new(64);
        // 18446744073709551615, -1, 0
        let items = d
            .feed(&[
                0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x20, 0x00,
            ])
            .unwrap();
        assert_eq!(items, vec![json!(u64::MAX), json!(-1), json!(0)]);
    }
}
