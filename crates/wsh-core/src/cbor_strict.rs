//! Strict CBOR well-formedness for wsh (#317). The Rust twin of the decoder in `src/cbor.mjs`; the two are held to the same table of inputs
//! (`spec/cbor-strict-cases.json`) and to each other by a differential test.
//!
//! [`validate`] walks one item without building anything (so there is nothing to allocate for a hostile length) and refuses, with a rule code:
//!
//! - a declared length (string, bytes, array, map) longer than what is left in the buffer, checked before anything is looped over: an array needs
//!   one byte per element and a map two per pair, so a head that claims 2^32 elements fails at once (`length-exceeds-buffer`; `truncated` is for
//!   a head or item that is cut off);
//! - bytes after the item ([`validate`]; [`item_end`] is the explicit way to read one item out of a longer buffer);
//! - integers and lengths that are not in the shortest form of their head (`non-shortest`);
//! - indefinite-length strings, arrays and maps (`indefinite-length`), a stray break (`unexpected-break`), reserved additional info;
//! - tags (`tag`), simple values other than false/true/null (`simple-value`);
//! - map keys that are not text (`non-text-key`) or that appear twice in one map (`duplicate-key`);
//! - text that is not UTF-8, and nesting deeper than [`MAX_DEPTH`].
//!
//! Floats of every width are accepted (the JS encoder writes float64 for everything; ciborium writes the shortest exact form). Map keys need not be
//! sorted: the JS encoder writes insertion order and this crate field order, so no canonical key order exists on the wire to require.
//!
//! One legacy exception ([`Options::legacy_indefinite_map`], on by default): the top-level item may be an indefinite-length map, which every wsh
//! Rust encoder released before this one wrote for a message envelope (`serde(flatten)` makes ciborium use one). Its contents are held to every rule.

use std::collections::HashSet;
use std::fmt;

/// The deepest nesting accepted. The rpc channel's scanners use the same bound.
pub const MAX_DEPTH: usize = 128;

/// Which rule an input broke (the same strings as `CborError.code` in `src/cbor.mjs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictCode {
    Truncated,
    LengthExceedsBuffer,
    TrailingBytes,
    NonShortest,
    IndefiniteLength,
    UnexpectedBreak,
    ReservedAdditionalInfo,
    DuplicateKey,
    NonTextKey,
    Tag,
    SimpleValue,
    InvalidUtf8,
    TooDeep,
}

impl StrictCode {
    pub fn as_str(self) -> &'static str {
        match self {
            StrictCode::Truncated => "truncated",
            StrictCode::LengthExceedsBuffer => "length-exceeds-buffer",
            StrictCode::TrailingBytes => "trailing-bytes",
            StrictCode::NonShortest => "non-shortest",
            StrictCode::IndefiniteLength => "indefinite-length",
            StrictCode::UnexpectedBreak => "unexpected-break",
            StrictCode::ReservedAdditionalInfo => "reserved-additional-info",
            StrictCode::DuplicateKey => "duplicate-key",
            StrictCode::NonTextKey => "non-text-key",
            StrictCode::Tag => "tag",
            StrictCode::SimpleValue => "simple-value",
            StrictCode::InvalidUtf8 => "invalid-utf8",
            StrictCode::TooDeep => "too-deep",
        }
    }
}

/// A malformed input: the rule and the byte offset it was broken at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrictError {
    pub code: StrictCode,
    pub offset: usize,
}

impl fmt::Display for StrictError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "malformed cbor ({}) at byte {}",
            self.code.as_str(),
            self.offset
        )
    }
}

impl std::error::Error for StrictError {}

/// What to accept beyond the strict rules.
#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Accept an indefinite-length map as the top-level item (see the module notes). Default true.
    pub legacy_indefinite_map: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            legacy_indefinite_map: true,
        }
    }
}

fn err(code: StrictCode, offset: usize) -> StrictError {
    StrictError { code, offset }
}

/// `data` must be exactly one acceptable item.
pub fn validate_with(data: &[u8], opts: &Options) -> Result<(), StrictError> {
    let end = item_end(data, 0, opts)?;
    if end != data.len() {
        return Err(err(StrictCode::TrailingBytes, end));
    }
    Ok(())
}

/// [`validate_with`] with the default options.
pub fn validate(data: &[u8]) -> Result<(), StrictError> {
    validate_with(data, &Options::default())
}

/// Where the ONE item that starts at `offset` ends; whatever follows is the caller's. Every rule that applies to the item applies.
pub fn item_end(data: &[u8], offset: usize, opts: &Options) -> Result<usize, StrictError> {
    let mut off = offset;
    item(data, &mut off, 0, opts)?;
    Ok(off)
}

/// The argument of a head (a `u64`, or `None` for additional info 31, which the caller handles).
fn argument(data: &[u8], off: &mut usize, ai: u8, start: usize) -> Result<u64, StrictError> {
    if ai < 24 {
        return Ok(ai as u64);
    }
    let size = match ai {
        24 => 1,
        25 => 2,
        26 => 4,
        _ => 8,
    };
    if *off + size > data.len() {
        return Err(err(StrictCode::Truncated, start));
    }
    let mut v: u64 = 0;
    for b in &data[*off..*off + size] {
        v = (v << 8) | *b as u64;
    }
    *off += size;
    let shortest = match size {
        1 => v >= 24,
        2 => v >= 0x100,
        4 => v >= 0x1_0000,
        _ => v >= 0x1_0000_0000,
    };
    if !shortest {
        return Err(err(StrictCode::NonShortest, start));
    }
    Ok(v)
}

/// A length that must fit what is left (`per_item` bytes at least for each item).
fn length(
    data: &[u8],
    off: &mut usize,
    ai: u8,
    start: usize,
    per_item: u64,
) -> Result<usize, StrictError> {
    let len = argument(data, off, ai, start)?;
    let left = (data.len() - *off) as u64;
    match len.checked_mul(per_item) {
        Some(need) if need <= left => Ok(len as usize),
        _ => Err(err(StrictCode::LengthExceedsBuffer, start)),
    }
}

fn item(data: &[u8], off: &mut usize, depth: usize, opts: &Options) -> Result<(), StrictError> {
    if depth > MAX_DEPTH {
        return Err(err(StrictCode::TooDeep, *off));
    }
    let start = *off;
    let Some(&initial) = data.get(start) else {
        return Err(err(StrictCode::Truncated, start));
    };
    *off += 1;
    let mt = initial >> 5;
    let ai = initial & 0x1f;
    if (28..=30).contains(&ai) {
        return Err(err(StrictCode::ReservedAdditionalInfo, start));
    }
    if ai == 31 {
        return match mt {
            0 | 1 | 6 => Err(err(StrictCode::ReservedAdditionalInfo, start)),
            7 => Err(err(StrictCode::UnexpectedBreak, start)),
            5 if depth == 0 && opts.legacy_indefinite_map => legacy_map(data, off, depth, opts),
            _ => Err(err(StrictCode::IndefiniteLength, start)),
        };
    }
    match mt {
        0 | 1 => {
            argument(data, off, ai, start)?;
        }
        2 => {
            let len = length(data, off, ai, start, 1)?;
            *off += len;
        }
        3 => {
            let len = length(data, off, ai, start, 1)?;
            if std::str::from_utf8(&data[*off..*off + len]).is_err() {
                return Err(err(StrictCode::InvalidUtf8, start));
            }
            *off += len;
        }
        4 => {
            let len = length(data, off, ai, start, 1)?;
            for _ in 0..len {
                item(data, off, depth + 1, opts)?;
            }
        }
        5 => {
            let len = length(data, off, ai, start, 2)?;
            let mut keys: HashSet<&[u8]> = HashSet::new();
            for _ in 0..len {
                pair(data, off, depth, opts, &mut keys)?;
            }
        }
        6 => return Err(err(StrictCode::Tag, start)),
        _ => match ai {
            20..=22 => {}
            25 | 26 | 27 => {
                let size = 2usize << (ai - 25);
                if *off + size > data.len() {
                    return Err(err(StrictCode::Truncated, start));
                }
                *off += size;
            }
            24 if *off >= data.len() => return Err(err(StrictCode::Truncated, start)),
            _ => return Err(err(StrictCode::SimpleValue, start)),
        },
    }
    Ok(())
}

/// One key (text, not yet seen in this map) and its value.
fn pair<'a>(
    data: &'a [u8],
    off: &mut usize,
    depth: usize,
    opts: &Options,
    keys: &mut HashSet<&'a [u8]>,
) -> Result<(), StrictError> {
    let key_at = *off;
    if let Some(&b) = data.get(key_at) {
        if b >> 5 != 3 {
            return Err(err(StrictCode::NonTextKey, key_at));
        }
    }
    item(data, off, depth + 1, opts)?;
    // text in its shortest form and valid UTF-8: equal bytes are equal keys
    if !keys.insert(&data[key_at..*off]) {
        return Err(err(StrictCode::DuplicateKey, key_at));
    }
    item(data, off, depth + 1, opts)
}

fn legacy_map(
    data: &[u8],
    off: &mut usize,
    depth: usize,
    opts: &Options,
) -> Result<(), StrictError> {
    let mut keys: HashSet<&[u8]> = HashSet::new();
    loop {
        match data.get(*off) {
            None => return Err(err(StrictCode::Truncated, *off)),
            Some(0xff) => {
                *off += 1;
                return Ok(());
            }
            Some(_) => pair(data, off, depth, opts, &mut keys)?,
        }
    }
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
                (want, got) => wrong.push(format!(
                    "{hex}: wanted {want:?}, got {:?}",
                    got.map_err(|e| e.code.as_str())
                )),
            }
        }
        assert!(
            wrong.is_empty(),
            "{} of {} cases wrong:\n{}",
            wrong.len(),
            cases.len(),
            wrong.join("\n")
        );
    }

    #[test]
    fn declared_lengths_are_checked_before_anything_is_allocated() {
        let t0 = Instant::now();
        for hex in [
            "9affffffff",
            "9b0000000100000000",
            "9b0020000000000000",
            "9bffffffffffffffff",
            "bb0000000100000000",
            "bbffffffffffffffff",
            "5bffffffffffffffff",
            "7bffffffffffffffff",
            "7affffffff",
            "5affffffff",
        ] {
            let e = validate(&unhex(hex)).expect_err(hex);
            assert_eq!(e.code.as_str(), "length-exceeds-buffer", "{hex}");
        }
        assert!(t0.elapsed().as_millis() < 200);
    }

    #[test]
    fn the_issue_case_a_grown_session_id_length_is_an_error() {
        // {type: 0x8f, session_id: "abcd"} with the length head of "abcd" (0x64) raised
        let mut frame = unhex(
            "a2647479706518 8f6a73657373696f6e5f6964 64 61626364"
                .replace(' ', "")
                .as_str(),
        );
        assert!(validate(&frame).is_ok());
        let at = frame.len() - 5;
        assert_eq!(frame[at], 0x64);
        for bigger in [0x65u8, 0x66, 0x78, 0x7a, 0x7f] {
            frame[at] = bigger;
            assert!(validate(&frame).is_err(), "0x{bigger:02x}");
        }
        frame[at] = 0x63;
        assert_eq!(
            validate(&frame).unwrap_err().code.as_str(),
            "trailing-bytes"
        );
    }

    #[test]
    fn item_end_reads_one_item_from_an_offset_and_leaves_the_rest() {
        let both = unhex("0909a16161018201 02".replace(' ', "").as_str());
        let o = Options::default();
        let end = item_end(&both, 2, &o).unwrap();
        assert_eq!(end, 6);
        assert_eq!(item_end(&both, end, &o).unwrap(), both.len());
        assert_eq!(
            item_end(&unhex("1800ff"), 0, &o).unwrap_err().code.as_str(),
            "non-shortest"
        );
    }

    #[test]
    fn golden_vectors_from_every_encoder_are_accepted_and_the_released_rust_ones_only_by_the_legacy_exception(
    ) {
        let v = doc(include_str!("../../../spec/cbor-vectors.json"));
        let strict = Options {
            legacy_indefinite_map: false,
        };
        let mut n = 0;
        for vec in v["vectors"].as_array().unwrap() {
            for side in ["js", "rust", "rust_released"] {
                let bytes = unhex(
                    vec[side]
                        .as_str()
                        .unwrap_or_else(|| panic!("{} has no {side}", vec["name"])),
                );
                validate(&bytes).unwrap_or_else(|e| panic!("{}/{side}: {e}", vec["name"]));
                let ciborium_ok: Result<ciborium::value::Value, _> =
                    ciborium::from_reader(bytes.as_slice());
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
                0 if !b.is_empty() => {
                    let i = rng.below(b.len());
                    b[i] ^= 1 << rng.below(8);
                }
                1 if !b.is_empty() => {
                    let i = rng.below(b.len());
                    b[i] = rng.next() as u8;
                }
                2 if !b.is_empty() => {
                    let i = rng.below(b.len());
                    b.remove(i);
                }
                3 => {
                    let i = rng.below(b.len() + 1);
                    b.insert(i, rng.next() as u8);
                }
                4 if !b.is_empty() => {
                    let n = rng.below(b.len());
                    b.truncate(n);
                }
                _ => b.push(rng.next() as u8),
            }
        }
        b
    }

    #[test]
    fn fuzz_fixed_seed_mutations_never_panic_never_hang_and_what_is_accepted_is_also_valid_cbor() {
        let v = doc(include_str!("../../../spec/cbor-vectors.json"));
        let corpus: Vec<Vec<u8>> = v["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|x| ["js", "rust"].map(|s| unhex(x[s].as_str().unwrap())))
            .collect();
        let mut rng = Rng(0x2545_F491_4F6C_DD1D);
        let t0 = Instant::now();
        let (mut accepted, mut rejected) = (0, 0);
        for _ in 0..40_000 {
            let src = &corpus[rng.below(corpus.len())];
            let m = mutate(&mut rng, src);
            match validate(&m) {
                Ok(()) => {
                    accepted += 1;
                    let parsed: Result<ciborium::value::Value, _> =
                        ciborium::from_reader(m.as_slice());
                    assert!(
                        parsed.is_ok(),
                        "accepted by the strict validator but not by ciborium: {}",
                        hex::encode(&m)
                    );
                }
                Err(_) => rejected += 1,
            }
        }
        assert!(t0.elapsed().as_secs() < 20, "fuzz took {:?}", t0.elapsed());
        assert!(
            accepted > 1000 && rejected > 1000,
            "{accepted} accepted, {rejected} rejected"
        );
    }
}
