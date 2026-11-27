//! Strict CBOR well-formedness for wsh (#317). STUB: accepts everything, so the tests below are red.

use std::fmt;

/// Which rule an input broke (the same codes as `CborError.code` in `src/cbor.mjs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictCode {
    Truncated,
}

impl StrictCode {
    pub fn as_str(self) -> &'static str {
        match self {
            StrictCode::Truncated => "truncated",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrictError {
    pub code: StrictCode,
    pub offset: usize,
}

impl fmt::Display for StrictError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed cbor ({}) at byte {}", self.code.as_str(), self.offset)
    }
}

impl std::error::Error for StrictError {}

#[derive(Debug, Clone, Copy)]
pub struct Options {
    pub legacy_indefinite_map: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options { legacy_indefinite_map: true }
    }
}

pub fn validate_with(_data: &[u8], _opts: &Options) -> Result<(), StrictError> {
    Ok(())
}

pub fn validate(data: &[u8]) -> Result<(), StrictError> {
    validate_with(data, &Options::default())
}

pub fn item_end(data: &[u8], _offset: usize, _opts: &Options) -> Result<usize, StrictError> {
    Ok(data.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value as J;
    use std::time::Instant;

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    fn doc(text: &str) -> J {
        serde_json::from_str(text).unwrap()
    }

    #[test]
    fn the_shared_table_of_malformed_and_accepted_inputs() {
        let table = doc(include_str!("../../../spec/cbor-strict-cases.json"));
        let cases = table["cases"].as_array().unwrap();
        assert!(cases.len() > 100);
        let mut wrong = Vec::new();
        for c in cases {
            let hex = c["hex"].as_str().unwrap();
            let opts = Options {
                legacy_indefinite_map: c.get("legacy").and_then(|v| v.as_bool()).unwrap_or(true),
            };
            let got = validate_with(&unhex(hex), &opts);
            match (c["error"].as_str(), got) {
                (None, Ok(())) => {}
                (Some(want), Err(e)) if e.code.as_str() == want => {}
                (want, got) => wrong.push(format!("{hex}: wanted {want:?}, got {:?}", got.map_err(|e| e.code.as_str()))),
            }
        }
        assert!(wrong.is_empty(), "{} of {} cases wrong:\n{}", wrong.len(), cases.len(), wrong.join("\n"));
    }

    #[test]
    fn declared_lengths_are_checked_before_anything_is_allocated() {
        let t0 = Instant::now();
        for hex in [
            "9affffffff", "9b0000000100000000", "9b0020000000000000", "9bffffffffffffffff", "bb0000000100000000", "bbffffffffffffffff",
            "5bffffffffffffffff", "7bffffffffffffffff", "7affffffff", "5affffffff",
        ] {
            let e = validate(&unhex(hex)).expect_err(hex);
            assert_eq!(e.code.as_str(), "length-exceeds-buffer", "{hex}");
        }
        assert!(t0.elapsed().as_millis() < 200);
    }

    #[test]
    fn the_issue_case_a_grown_session_id_length_is_an_error() {
        // {type: 0x8f, session_id: "abcd"} with the length head of "abcd" (0x64) raised
        let mut frame = unhex("a2647479706518 8f6a73657373696f6e5f6964 64 61626364".replace(' ', "").as_str());
        assert!(validate(&frame).is_ok());
        let at = frame.len() - 5;
        assert_eq!(frame[at], 0x64);
        for bigger in [0x65u8, 0x66, 0x78, 0x7a, 0x7f] {
            frame[at] = bigger;
            assert!(validate(&frame).is_err(), "0x{bigger:02x}");
        }
        frame[at] = 0x63;
        assert_eq!(validate(&frame).unwrap_err().code.as_str(), "trailing-bytes");
    }

    #[test]
    fn item_end_reads_one_item_from_an_offset_and_leaves_the_rest() {
        let both = unhex("0909a16161018201 02".replace(' ', "").as_str());
        let o = Options::default();
        let end = item_end(&both, 2, &o).unwrap();
        assert_eq!(end, 6);
        assert_eq!(item_end(&both, end, &o).unwrap(), both.len());
        assert_eq!(item_end(&unhex("1800ff"), 0, &o).unwrap_err().code.as_str(), "non-shortest");
    }

    #[test]
    fn golden_vectors_from_every_encoder_are_accepted_and_the_released_rust_ones_only_by_the_legacy_exception() {
        let v = doc(include_str!("../../../spec/cbor-vectors.json"));
        let strict = Options { legacy_indefinite_map: false };
        let mut n = 0;
        for vec in v["vectors"].as_array().unwrap() {
            for side in ["js", "rust", "rust_released"] {
                let bytes = unhex(vec[side].as_str().unwrap_or_else(|| panic!("{} has no {side}", vec["name"])));
                validate(&bytes).unwrap_or_else(|e| panic!("{}/{side}: {e}", vec["name"]));
                let ciborium_ok: Result<ciborium::value::Value, _> = ciborium::from_reader(bytes.as_slice());
                assert!(ciborium_ok.is_ok());
                let canonical = validate_with(&bytes, &strict);
                if side == "rust_released" && vec["layer"] == "control" {
                    assert_eq!(canonical.unwrap_err().code.as_str(), "indefinite-length");
                } else {
                    canonical.unwrap_or_else(|e| panic!("{}/{side}: {e}", vec["name"]));
                }
                n += 1;
            }
        }
        assert!(n >= 600, "{n}");
    }

    /// A fixed-seed xorshift: the same mutations on every run.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    fn mutate(rng: &mut Rng, src: &[u8]) -> Vec<u8> {
        let mut b = src.to_vec();
        for _ in 0..=rng.below(3) {
            match rng.below(6) {
                0 if !b.is_empty() => { let i = rng.below(b.len()); b[i] ^= 1 << rng.below(8); }
                1 if !b.is_empty() => { let i = rng.below(b.len()); b[i] = rng.next() as u8; }
                2 if !b.is_empty() => { let i = rng.below(b.len()); b.remove(i); }
                3 => { let i = rng.below(b.len() + 1); b.insert(i, rng.next() as u8); }
                4 if !b.is_empty() => { let n = rng.below(b.len()); b.truncate(n); }
                _ => b.push(rng.next() as u8),
            }
        }
        b
    }

    #[test]
    fn fuzz_fixed_seed_mutations_never_panic_never_hang_and_what_is_accepted_is_also_valid_cbor() {
        let v = doc(include_str!("../../../spec/cbor-vectors.json"));
        let corpus: Vec<Vec<u8>> = v["vectors"].as_array().unwrap().iter().flat_map(|x| ["js", "rust"].map(|s| unhex(x[s].as_str().unwrap()))).collect();
        let mut rng = Rng(0x2545_F491_4F6C_DD1D);
        let t0 = Instant::now();
        let (mut accepted, mut rejected) = (0, 0);
        for _ in 0..40_000 {
            let src = &corpus[rng.below(corpus.len())];
            let m = mutate(&mut rng, src);
            match validate(&m) {
                Ok(()) => {
                    accepted += 1;
                    let parsed: Result<ciborium::value::Value, _> = ciborium::from_reader(m.as_slice());
                    assert!(parsed.is_ok(), "accepted by the strict validator but not by ciborium: {}", hex::encode(&m));
                }
                Err(_) => rejected += 1,
            }
        }
        assert!(t0.elapsed().as_secs() < 20, "fuzz took {:?}", t0.elapsed());
        assert!(accepted > 1000 && rejected > 1000, "{accepted} accepted, {rejected} rejected");
    }
}
