//! Differential-test helper (#325): reads one hex-encoded CBOR item per line on stdin, reads it leniently (the compatibility window's options), and prints
//! the canonical re-encoding of what it read as hex (`wsh_core::cbor_canon::value_to_vec`), or `err <rule code>` if the item is refused. A line ends with
//! ` intfloat` when the item holds an integral float inside the 64-bit integer range: JS has one number type and writes that as an integer, so the
//! two encoders legitimately differ there (see the notes in `cbor_canon.rs`).
//! `test/rust/cbor-differential.test.mjs` compares this with the JS decoder + encoder (`cborEncode(cborDecode(x))`): the two encoders must agree byte for byte.
//!
//!     cargo build -p wsh-core --example cbor_canon
use std::io::{BufRead, Write};

fn main() {
    let stdin = std::io::stdin();
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        let bytes = hex::decode(line.trim()).unwrap_or_default();
        let verdict = match wsh_core::cbor_strict::validate(&bytes) {
            Err(e) => format!("err {}", e.code.as_str()),
            Ok(()) => match ciborium::from_reader::<ciborium::value::Value, _>(bytes.as_slice()) {
                Ok(v) => match wsh_core::cbor_canon::value_to_vec(&v) {
                    Ok(b) if has_integral_float(&v) => format!("{} intfloat", hex::encode(b)),
                    Ok(b) => hex::encode(b),
                    Err(_) => "err canon".to_string(),
                },
                Err(_) => "err ciborium".to_string(),
            },
        };
        writeln!(out, "{verdict}").unwrap();
    }
}

/// An integral float that JS would write as an integer: whole, not -0, within -2^64 ..= 2^64-1.
fn has_integral_float(v: &ciborium::value::Value) -> bool {
    use ciborium::value::Value;
    match v {
        Value::Float(f) => {
            f.fract() == 0.0
                && !(*f == 0.0 && f.is_sign_negative())
                && *f >= -18446744073709551616.0
                && *f < 18446744073709551616.0
        }
        Value::Array(a) => a.iter().any(has_integral_float),
        Value::Map(m) => m
            .iter()
            .any(|(k, v)| has_integral_float(k) || has_integral_float(v)),
        _ => false,
    }
}
