//! Adds the Rust encoder side to `spec/cbor-vectors.json` (#317): every vector the JS encoder wrote is decoded with the typed
//! decoder (`decode_envelope`, or `Cbor` for an rpc item) and re-encoded with the Rust encoder; the bytes go under `rust`.
//!
//!     cargo run -p wsh-core --example cbor_vectors            # rewrite spec/cbor-vectors.json
//!
//! Run it from the repository root. A vector the Rust decoder refuses gets `rust_error` instead of `rust`.
use serde_json::Value as J;

fn main() {
    let path = "spec/cbor-vectors.json";
    let mut doc: J =
        serde_json::from_str(&std::fs::read_to_string(path).expect("run from the repo root"))
            .unwrap();
    let mut failures = 0;
    for v in doc["vectors"].as_array_mut().unwrap() {
        let js = hex::decode(v["js"].as_str().unwrap()).unwrap();
        let layer = v["layer"].as_str().unwrap().to_string();
        let out: Result<Vec<u8>, String> = if layer == "control" {
            wsh_core::decode_envelope(&js)
                .map_err(|e| e.to_string())
                .and_then(|env| wsh_core::cbor_encode(&env).map_err(|e| e.to_string()))
        } else {
            ciborium::from_reader::<wsh_core::rpc_codec::Cbor, _>(js.as_slice())
                .map_err(|e| e.to_string())
                .and_then(|c| wsh_core::rpc_codec::encode_cbor(&c).map_err(|e| e.message))
        };
        let obj = v.as_object_mut().unwrap();
        match out {
            Ok(b) => {
                obj.insert("rust".into(), J::String(hex::encode(b)));
                obj.remove("rust_error");
            }
            Err(e) => {
                failures += 1;
                obj.remove("rust");
                obj.insert("rust_error".into(), J::String(e));
            }
        }
    }
    std::fs::write(path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
    eprintln!(
        "{} vectors, {} the Rust decoder refused",
        doc["vectors"].as_array().unwrap().len(),
        failures
    );
}
