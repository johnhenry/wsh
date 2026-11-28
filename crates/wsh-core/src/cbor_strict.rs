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
//! - more than [`MAX_CONTAINERS`] arrays and maps in one item (`too-many-containers`): a 4 MiB frame of empty arrays is 4 million of them.
//!
//! Canonical form (#325; RFC 8949 4.2.1, what [`crate::cbor_canon`] and `src/cbor.mjs` write), which released peers did not write, so it is required
//! only with [`Options::legacy_non_canonical`] off ([`Options::strict`]) and accepted by default for the compatibility window (COMPATIBILITY.md rule 7):
//!
//! - map keys sorted by the bytes of their encoding, shorter first, then bytewise (`non-canonical-key-order`);
//! - floats in the shortest width that reads back exactly, one NaN (`f97e00`): no float32/float64 that fits a narrower width, no NaN payload or sign
//!   (`non-canonical-float`); `-0` is `f98000` and allowed.
//!
//! Two legacy exceptions, both on by default and both off in [`Options::strict`]: [`Options::legacy_indefinite_map`] (the top-level item, at offset 0, may be an
//! indefinite-length map, which every wsh Rust encoder released before this one wrote for a message envelope: `serde(flatten)` makes ciborium use one;
//! its contents are held to every rule) and [`Options::legacy_non_canonical`].

use std::collections::HashSet;
use std::fmt;

/// The deepest nesting accepted. The rpc channel's scanners use the same bound.
pub const MAX_DEPTH: usize = 128;

/// The most arrays and maps (counting the top-level item) one item may hold by default (`Options::max_containers`); the JS decoder's `CBOR_MAX_CONTAINERS`.
pub const MAX_CONTAINERS: usize = 1_000_000;

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
    TooManyContainers,
    NonCanonicalKeyOrder,
    NonCanonicalFloat,
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
            StrictCode::TooManyContainers => "too-many-containers",
            StrictCode::NonCanonicalKeyOrder => "non-canonical-key-order",
            StrictCode::NonCanonicalFloat => "non-canonical-float",
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

/// What to accept beyond the strict rules: the compatibility window of COMPATIBILITY.md rule 7. [`Options::default`] is the window as it is now (both
/// legacy options on); [`Options::strict`] is what the tests and the differential run and what becomes the default when the window closes.
#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Accept an indefinite-length map as the top-level item, at offset 0 (see the module notes). Default true.
    pub legacy_indefinite_map: bool,
    /// Accept the map key order, float widths and NaN forms the released encoders wrote (see the module notes). Default true.
    pub legacy_non_canonical: bool,
    /// The most arrays and maps one item may hold (the JS decoder's `maxContainers`; #336). Default [`MAX_CONTAINERS`], in every mode.
    pub max_containers: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            legacy_indefinite_map: true,
            legacy_non_canonical: true,
            max_containers: MAX_CONTAINERS,
        }
    }
}

impl Options {
    /// Every legacy option off: exactly one canonical encoding of every value.
    pub const fn strict() -> Self {
        Options {
            legacy_indefinite_map: false,
            legacy_non_canonical: false,
            max_containers: MAX_CONTAINERS,
        }
    }

    /// These options with the container cap set to `max_containers` (the other options unchanged).
    pub const fn with_max_containers(mut self, max_containers: usize) -> Self {
        self.max_containers = max_containers;
        self
    }
}

/// What one walk over one item carries: the options, whether a legacy map is allowed here, and the container count.
struct Walk<'o> {
    opts: &'o Options,
    legacy_top: bool,
    containers: usize,
}

impl Walk<'_> {
    fn container(&mut self, at: usize) -> Result<(), StrictError> {
        self.containers += 1;
        if self.containers > self.opts.max_containers {
            return Err(err(StrictCode::TooManyContainers, at));
        }
        Ok(())
    }
}

/// The keys of one map so far: the ones seen (a duplicate is an error) and the last one (canonical order).
struct Keys<'a> {
    seen: HashSet<&'a [u8]>,
    prev: Option<&'a [u8]>,
}

impl Keys<'_> {
    fn new() -> Self {
        Keys {
            seen: HashSet::new(),
            prev: None,
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

/// [`validate_with`] with the default options (the compatibility window).
pub fn validate(data: &[u8]) -> Result<(), StrictError> {
    validate_with(data, &Options::default())
}

/// Where the ONE item that starts at `offset` ends; whatever follows is the caller's. Every rule that applies to the item applies. The legacy
/// indefinite-length map is the top-level item of a message, so it is read at offset 0 only; the container count starts again at each call.
pub fn item_end(data: &[u8], offset: usize, opts: &Options) -> Result<usize, StrictError> {
    let mut off = offset;
    let mut walk = Walk {
        opts,
        legacy_top: opts.legacy_indefinite_map && offset == 0,
        containers: 0,
    };
    item(data, &mut off, 0, &mut walk)?;
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

fn item(data: &[u8], off: &mut usize, depth: usize, w: &mut Walk) -> Result<(), StrictError> {
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
            5 if depth == 0 && w.legacy_top => {
                w.container(start)?;
                legacy_map(data, off, depth, w)
            }
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
            w.container(start)?;
            for _ in 0..len {
                item(data, off, depth + 1, w)?;
            }
        }
        5 => {
            let len = length(data, off, ai, start, 2)?;
            w.container(start)?;
            let mut keys = Keys::new();
            for _ in 0..len {
                pair(data, off, depth, w, &mut keys)?;
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
                if !w.opts.legacy_non_canonical && !float_is_canonical(&data[*off..*off + size]) {
                    return Err(err(StrictCode::NonCanonicalFloat, start));
                }
                *off += size;
            }
            24 if *off >= data.len() => return Err(err(StrictCode::Truncated, start)),
            _ => return Err(err(StrictCode::SimpleValue, start)),
        },
    }
    Ok(())
}

/// Is the float whose 2, 4 or 8 content bytes these are the shortest form of its value? NaN has one form (`f97e00`).
fn float_is_canonical(raw: &[u8]) -> bool {
    use crate::cbor_canon::f16_bits_exact;
    match raw.len() {
        2 => {
            let h = u16::from_be_bytes([raw[0], raw[1]]);
            // a half NaN is exponent all ones and a non-zero mantissa: only the quiet NaN without payload or sign is canonical
            !(h & 0x7c00 == 0x7c00 && h & 0x03ff != 0) || h == 0x7e00
        }
        4 => {
            let f = f32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
            !f.is_nan() && f16_bits_exact(f as f64).is_none()
        }
        _ => {
            let f = f64::from_be_bytes([
                raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
            ]);
            !f.is_nan() && ((f as f32) as f64).to_bits() != f.to_bits()
        }
    }
}

/// One key (text, not yet seen in this map, and with canonical options after the one before it) and its value.
fn pair<'a>(
    data: &'a [u8],
    off: &mut usize,
    depth: usize,
    w: &mut Walk,
    keys: &mut Keys<'a>,
) -> Result<(), StrictError> {
    let key_at = *off;
    if let Some(&b) = data.get(key_at) {
        if b >> 5 != 3 {
            return Err(err(StrictCode::NonTextKey, key_at));
        }
    }
    item(data, off, depth + 1, w)?;
    // text in its shortest form and valid UTF-8: equal bytes are equal keys
    let key = &data[key_at..*off];
    if !keys.seen.insert(key) {
        return Err(err(StrictCode::DuplicateKey, key_at));
    }
    if !w.opts.legacy_non_canonical {
        // RFC 8949 4.2.1: shorter encoded keys first, then bytewise
        if let Some(prev) = keys.prev {
            if prev.len() > key.len() || (prev.len() == key.len() && prev > key) {
                return Err(err(StrictCode::NonCanonicalKeyOrder, key_at));
            }
        }
        keys.prev = Some(key);
    }
    item(data, off, depth + 1, w)
}

fn legacy_map(data: &[u8], off: &mut usize, depth: usize, w: &mut Walk) -> Result<(), StrictError> {
    let mut keys = Keys::new();
    loop {
        match data.get(*off) {
            None => return Err(err(StrictCode::Truncated, *off)),
            Some(0xff) => {
                *off += 1;
                return Ok(());
            }
            Some(_) => pair(data, off, depth, w, &mut keys)?,
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
                ..Options::default()
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
    fn golden_vectors_from_every_encoder_are_accepted_in_the_window_and_the_current_ones_in_strict_mode(
    ) {
        let v = doc(include_str!("../../../spec/cbor-vectors.json"));
        let strict = Options::strict();
        let mut n = 0;
        for vec in v["vectors"].as_array().unwrap() {
            for side in ["js", "rust", "js_released", "rust_released"] {
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
                } else if side.ends_with("_released") {
                    // a released encoder's bytes are canonical exactly where they equal the current encoders' bytes
                    let current = vec[side.trim_end_matches("_released")].as_str().unwrap();
                    let same = vec[side].as_str().unwrap() == current;
                    match canonical {
                        Ok(()) => assert!(same, "{}/{side}", vec["name"]),
                        Err(e) => {
                            assert!(!same, "{}/{side}: {e}", vec["name"]);
                            assert!(
                                ["non-canonical-key-order", "non-canonical-float"]
                                    .contains(&e.code.as_str()),
                                "{}/{side}: {e}",
                                vec["name"]
                            );
                        }
                    }
                } else {
                    canonical.unwrap_or_else(|e| panic!("{}/{side}: {e}", vec["name"]));
                }
                n += 1;
            }
        }
        assert!(n >= 800, "{n}");
    }

    #[test]
    fn the_shared_table_of_canonical_cases_holds_in_strict_mode_and_in_the_window() {
        let table = doc(include_str!("../../../spec/cbor-strict-cases.json"));
        let cases = table["canonical_cases"].as_array().unwrap();
        assert!(cases.len() >= 40, "{}", cases.len());
        let mut wrong = Vec::new();
        for c in cases {
            let hex = c["hex"].as_str().unwrap();
            let bytes = unhex(hex);
            let want = c["error"].as_str();
            let want_default = c.get("default_error").and_then(|v| v.as_str());
            for (label, opts, want) in [
                ("strict", Options::strict(), want),
                ("default", Options::default(), want_default),
            ] {
                let got = validate_with(&bytes, &opts).err().map(|e| e.code.as_str());
                if got != want {
                    wrong.push(format!("{label} {hex}: wanted {want:?}, got {got:?}"));
                }
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    #[test]
    fn the_options_are_independent_and_strict_turns_both_off() {
        let unsorted = unhex("a26162016161 02".replace(' ', "").as_str());
        let indefinite = unhex("bf616101ff");
        let only_order = Options {
            legacy_indefinite_map: true,
            legacy_non_canonical: false,
            ..Options::default()
        };
        assert!(validate(&unsorted).is_ok());
        assert_eq!(
            validate_with(&unsorted, &Options::strict())
                .unwrap_err()
                .code
                .as_str(),
            "non-canonical-key-order"
        );
        assert!(validate_with(&indefinite, &only_order).is_ok());
        assert_eq!(
            validate_with(&indefinite, &Options::strict())
                .unwrap_err()
                .code
                .as_str(),
            "indefinite-length"
        );
        let only_indef_off = Options {
            legacy_indefinite_map: false,
            legacy_non_canonical: true,
            ..Options::default()
        };
        assert!(validate_with(&unsorted, &only_indef_off).is_ok());
        assert!(validate_with(&indefinite, &only_indef_off).is_err());
    }

    #[test]
    fn the_legacy_map_is_read_at_offset_zero_only() {
        let o = Options::default();
        assert_eq!(item_end(&unhex("bf616101ff00"), 0, &o).unwrap(), 5);
        let after = unhex("0abf616101ff");
        assert_eq!(item_end(&after, 0, &o).unwrap(), 1);
        assert_eq!(
            item_end(&after, 1, &o).unwrap_err().code.as_str(),
            "indefinite-length"
        );
        let two = unhex("00bf616101ff");
        let end = item_end(&two, 0, &o).unwrap();
        assert_eq!(
            item_end(&two, end, &o).unwrap_err().code.as_str(),
            "indefinite-length"
        );
    }

    #[test]
    fn every_half_float_is_canonical_as_a_half_and_never_as_a_single_or_double() {
        use crate::cbor_canon::f16_to_f64;
        let strict = Options::strict();
        let mut halves = 0;
        for h in 0u32..0x1_0000 {
            let h = h as u16;
            let half = [vec![0xf9], h.to_be_bytes().to_vec()].concat();
            let v = f16_to_f64(h);
            if v.is_nan() {
                // only the quiet NaN with no payload and no sign is canonical
                assert_eq!(
                    validate_with(&half, &strict).is_ok(),
                    h == 0x7e00,
                    "{h:04x}"
                );
                continue;
            }
            assert!(validate_with(&half, &strict).is_ok(), "{h:04x}");
            let single = [vec![0xfa], (v as f32).to_be_bytes().to_vec()].concat();
            let double = [vec![0xfb], v.to_be_bytes().to_vec()].concat();
            for wide in [single, double] {
                assert_eq!(
                    validate_with(&wide, &strict).unwrap_err().code.as_str(),
                    "non-canonical-float",
                    "{h:04x}"
                );
                assert!(validate(&wide).is_ok(), "{h:04x} (the window reads it)");
            }
            halves += 1;
        }
        assert_eq!(halves, 0x1_0000 - 2046);
    }

    /// `Options::max_containers` is the Rust `maxContainers` of the JS decoder (#336): the cap is the option's, the default is MAX_CONTAINERS.
    #[test]
    fn the_container_cap_is_an_option() {
        // an array of N empty arrays holds N + 1 containers
        let arrays = |n: u8| {
            let mut b = vec![0x80 + n];
            b.resize(1 + n as usize, 0x80);
            b
        };
        assert_eq!(Options::default().max_containers, MAX_CONTAINERS);
        assert_eq!(Options::strict().max_containers, MAX_CONTAINERS);
        for base in [Options::default(), Options::strict()] {
            let three = base.with_max_containers(3);
            assert!(
                validate_with(&arrays(2), &three).is_ok(),
                "3 containers under a cap of 3"
            );
            assert_eq!(
                validate_with(&arrays(3), &three).unwrap_err().code.as_str(),
                "too-many-containers"
            );
            assert!(validate_with(&arrays(3), &base.with_max_containers(4)).is_ok());
            // the cap is the option's alone: the other options are as they were
            assert_eq!(three.legacy_indefinite_map, base.legacy_indefinite_map);
            assert_eq!(three.legacy_non_canonical, base.legacy_non_canonical);
            // the walk reports it at the container that crossed the cap
            assert_eq!(validate_with(&arrays(3), &three).unwrap_err().offset, 3);
        }
        assert!(
            validate_with(&arrays(20), &Options::default()).is_ok(),
            "the default is the old constant"
        );
    }

    #[test]
    fn a_container_cap_bounds_what_a_frame_of_empty_arrays_can_cost() {
        let strict = Options::strict();
        // an array of N empty arrays holds N + 1 containers
        let arrays = |n: usize| {
            let mut b = vec![0x9a];
            b.extend_from_slice(&(n as u32).to_be_bytes());
            b.resize(5 + n, 0x80);
            b
        };
        assert!(validate_with(&arrays(MAX_CONTAINERS - 1), &strict).is_ok());
        for opts in [strict, Options::default()] {
            assert_eq!(
                validate_with(&arrays(MAX_CONTAINERS), &opts)
                    .unwrap_err()
                    .code
                    .as_str(),
                "too-many-containers"
            );
        }
        let t0 = Instant::now();
        let four_mib = arrays(4 * 1024 * 1024 - 5);
        assert_eq!(
            validate(&four_mib).unwrap_err().code.as_str(),
            "too-many-containers"
        );
        assert!(t0.elapsed().as_millis() < 1500, "{:?}", t0.elapsed());
        // maps count, scalars and byte strings do not, and the legacy map counts as one
        assert!(validate(&unhex("85016161 41ff f6 f5".replace(' ', "").as_str())).is_ok());
        assert!(validate(&unhex("bf616101ff")).is_ok());
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
