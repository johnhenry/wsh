//! Differential-test helper (#317): reads one hex-encoded CBOR item per line on stdin and prints, per line, `ok` if
//! `wsh_core::cbor_decode` accepts it as a `Value`, or `err <rule code>` (`err ciborium` when the strict check passed but
//! ciborium refused). `test/rust/cbor-differential.test.mjs` feeds it the same inputs as the JS decoder and compares.
//!
//!     cargo build -p wsh-core --example cbor_accept
use std::io::{BufRead, Write};

fn main() {
    let stdin = std::io::stdin();
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        let bytes = hex::decode(line.trim()).unwrap_or_default();
        let verdict = match wsh_core::cbor_strict::validate(&bytes) {
            Err(e) => format!("err {}", e.code.as_str()),
            Ok(()) => match wsh_core::cbor_decode::<ciborium::value::Value>(&bytes) {
                Ok(_) => "ok".to_string(),
                Err(_) => "err ciborium".to_string(),
            },
        };
        writeln!(out, "{verdict}").unwrap();
    }
}
