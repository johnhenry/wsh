//! Differential-test helper (#317, #325): reads one hex-encoded CBOR item per line on stdin and prints, per line, `ok` if
//! `wsh_core::cbor_decode_with` accepts it as a `Value`, or `err <rule code>` (`err ciborium` when the strict check passed but
//! ciborium refused). `--strict` runs with every legacy option off (`Options::strict`), the default with the compatibility window's.
//! `test/rust/cbor-differential.test.mjs` feeds it the same inputs as the JS decoder and compares.
//!
//!     cargo build -p wsh-core --example cbor_accept
use std::io::{BufRead, Write};

fn main() {
    let opts = if std::env::args().any(|a| a == "--strict") {
        wsh_core::cbor_strict::Options::strict()
    } else {
        wsh_core::cbor_strict::Options::default()
    };
    let stdin = std::io::stdin();
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        let bytes = hex::decode(line.trim()).unwrap_or_default();
        let verdict = match wsh_core::cbor_strict::validate_with(&bytes, &opts) {
            Err(e) => format!("err {}", e.code.as_str()),
            Ok(()) => match wsh_core::cbor_decode_with::<ciborium::value::Value>(&bytes, &opts) {
                Ok(_) => "ok".to_string(),
                Err(_) => "err ciborium".to_string(),
            },
        };
        writeln!(out, "{verdict}").unwrap();
    }
}
