//! Interop helper (#335): reads one hex-encoded message envelope (a bare CBOR payload, no length prefix) per line on stdin and prints, per
//! line, `ok <payload as JSON>` if `wsh_core::decode_envelope` types it, or `err <message>`. `test/rust/f64-integral.test.mjs` feeds it what the
//! JS encoder writes and checks the Rust typed decode of every `f64` field in the spec.
//!
//!     cargo build -p wsh-core --example decode_envelope
use std::io::{BufRead, Write};

fn main() {
    let stdin = std::io::stdin();
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        let bytes = hex::decode(line.trim()).unwrap_or_default();
        let verdict = match wsh_core::decode_envelope(&bytes) {
            Ok(envelope) => format!("ok {}", serde_json::to_string(&envelope.payload).unwrap()),
            Err(e) => format!("err {}", e.to_string().replace('\n', " ")),
        };
        writeln!(out, "{verdict}").unwrap();
    }
}
