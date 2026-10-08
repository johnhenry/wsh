//! Incremental decoder for a CBOR sequence (RFC 8742).
//!
//! `feed()` bytes as they arrive, get back every item completed so far. Items
//! are self-delimiting, so there is no length prefix. An item larger than the
//! bound is refused as soon as it is detectable; malformed CBOR is an error
//! (`-32700`). Port of `CborSequenceDecoder` in `src/rpc.mjs`.

use super::{code, RpcError};
use ciborium::value::Value;

const MAX_DEPTH: usize = 128;

enum ScanError {
    Incomplete,
    Rpc(RpcError),
}

impl From<RpcError> for ScanError {
    fn from(e: RpcError) -> Self {
        ScanError::Rpc(e)
    }
}

fn parse_err(msg: &str) -> ScanError {
    ScanError::Rpc(RpcError::new(code::PARSE, msg))
}

/// End offset of the CBOR data item starting at `off`, or `Incomplete` if `buf` ends first.
/// Structure is validated just enough to find the item's end; ciborium does the decoding.
fn scan(buf: &[u8], mut off: usize, max: usize, depth: usize) -> Result<usize, ScanError> {
    if depth > MAX_DEPTH {
        return Err(parse_err("cbor nesting too deep"));
    }
    if off >= buf.len() {
        return Err(ScanError::Incomplete);
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
            return Err(ScanError::Incomplete);
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
                        return Err(ScanError::Incomplete);
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
                return Err(RpcError::too_large(
                    "message",
                    arg.min(usize::MAX as u64) as usize,
                    max,
                )
                .into());
            }
            let arg = arg as usize;
            if off + arg > buf.len() {
                return Err(ScanError::Incomplete);
            }
            Ok(off + arg)
        }
        4 | 5 => {
            let per = if mt == 5 { 2 } else { 1 };
            if indefinite {
                loop {
                    if off >= buf.len() {
                        return Err(ScanError::Incomplete);
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
                return Err(RpcError::too_large(
                    "message",
                    arg.min(usize::MAX as u64) as usize,
                    max,
                )
                .into());
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

#[derive(Debug)]
pub struct CborSequenceDecoder {
    buf: Vec<u8>,
    max: usize,
}

impl CborSequenceDecoder {
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

    /// Feed bytes; returns every item completed so far. On error the buffer is dropped.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<Value>, RpcError> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        let mut off = 0usize;
        let result = (|| -> Result<(), RpcError> {
            while off < self.buf.len() {
                let end = match scan(&self.buf, off, self.max, 0) {
                    Ok(end) => end,
                    Err(ScanError::Incomplete) => {
                        if self.buf.len() - off > self.max {
                            return Err(RpcError::too_large(
                                "message",
                                self.buf.len() - off,
                                self.max,
                            ));
                        }
                        break;
                    }
                    Err(ScanError::Rpc(e)) => return Err(e),
                };
                if end - off > self.max {
                    return Err(RpcError::too_large("message", end - off, self.max));
                }
                let item: Value = ciborium::from_reader(&self.buf[off..end])
                    .map_err(|e| RpcError::new(code::PARSE, format!("malformed cbor: {e}")))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(v: &Value) -> Vec<u8> {
        let mut b = Vec::new();
        ciborium::into_writer(v, &mut b).unwrap();
        b
    }

    #[test]
    fn decodes_items_split_at_every_byte() {
        let a = super::super::map([("a", super::super::int(1))]);
        let b = Value::Bytes(vec![7; 300]);
        let mut bytes = enc(&a);
        bytes.extend(enc(&b));
        let mut d = CborSequenceDecoder::new(1024);
        let mut got = Vec::new();
        for byte in &bytes {
            got.extend(d.feed(&[*byte]).unwrap());
        }
        assert_eq!(got, vec![a, b]);
        assert_eq!(d.pending(), 0);
    }

    #[test]
    fn several_items_in_one_chunk() {
        let mut bytes = enc(&Value::Text("x".into()));
        bytes.extend(enc(&Value::Text("y".into())));
        let mut d = CborSequenceDecoder::new(64);
        assert_eq!(d.feed(&bytes).unwrap().len(), 2);
    }

    #[test]
    fn refuses_an_oversized_item_as_soon_as_its_header_is_seen() {
        let mut d = CborSequenceDecoder::new(100);
        // byte string of 1000 bytes: only the 3-byte header arrives
        let e = d.feed(&[0x59, 0x03, 0xe8]).unwrap_err();
        assert_eq!(e.code, code::INVALID_REQUEST);
        assert!(e.message.contains("exceeds the 100 byte rpc message limit"));
        assert_eq!(d.pending(), 0);
    }

    #[test]
    fn refuses_a_buffered_item_over_the_bound() {
        let mut d = CborSequenceDecoder::new(10);
        // an indefinite array that never ends
        let mut bytes = vec![0x9f];
        bytes.extend(std::iter::repeat(0x01).take(20));
        let e = d.feed(&bytes).unwrap_err();
        assert_eq!(e.code, code::INVALID_REQUEST);
    }

    #[test]
    fn malformed_cbor_is_a_parse_error() {
        for bad in [&[0x1c][..], &[0xff][..], &[0x1f][..], &[0xdf, 0x01][..]] {
            let mut d = CborSequenceDecoder::new(64);
            let e = d.feed(bad).unwrap_err();
            assert_eq!(e.code, code::PARSE, "{bad:?}");
        }
    }

    #[test]
    fn rejects_deep_nesting() {
        let mut d = CborSequenceDecoder::new(4096);
        let bytes = vec![0x81; 300]; // 300 nested single-element arrays
        let e = d.feed(&bytes).unwrap_err();
        assert_eq!(e.code, code::PARSE);
    }

    #[test]
    fn indefinite_strings_and_maps_decode() {
        let mut d = CborSequenceDecoder::new(64);
        // (_ "a", "b")  and {_ "k": 1}
        let items = d
            .feed(&[
                0x7f, 0x61, b'a', 0x61, b'b', 0xff, 0xbf, 0x61, b'k', 0x01, 0xff,
            ])
            .unwrap();
        assert_eq!(items[0], Value::Text("ab".into()));
        assert_eq!(items.len(), 2);
    }
}
