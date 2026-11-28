//! The canonical CBOR encoder for wsh (#325): RFC 8949 section 4.2.1 deterministic encoding, byte for byte what `src/cbor.mjs` writes.
//!
//! - map keys sorted by the bytes of their encoding, shorter first, then bytewise (so for text keys: UTF-8 length, then UTF-8 bytes);
//! - the shortest head for every integer and length (ciborium already did this); definite lengths only (serde's `flatten` made ciborium write
//!   an indefinite-length map, so nothing here goes through ciborium's writer);
//! - the shortest float that reads back exactly (half, then single, then double), one NaN (`f97e00`), `-0` as `f98000`.
//!
//! The value is serialized to a [`Value`] tree first and written from there: a struct's fields are therefore sorted, whatever order they are
//! declared in. Two keys that encode alike are an error (the decoders refuse a duplicate key).
//!
//! One thing a byte comparison with the JS encoder cannot show: JS has one number type, so it writes an integral number as an integer, and this
//! encoder writes a Rust `f64` of the same value as a float (`f64` 1.0 is `f93c00`, JS 1 is `01`). Both are canonical, both are read by both
//! decoders; they are different values only to the typed Rust decoder (see `float_is_not_integer_in_typed_decode` below and COMPATIBILITY.md).

use ciborium::value::Value;
use serde::Serialize;
use std::fmt;

/// Why a value could not be written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonError(pub String);

impl fmt::Display for CanonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cannot encode as canonical cbor: {}", self.0)
    }
}

impl std::error::Error for CanonError {}

/// `value` as canonical CBOR.
pub fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, CanonError> {
    let tree = Value::serialized(value).map_err(|e| CanonError(e.to_string()))?;
    value_to_vec(&tree)
}

/// A [`Value`] tree as canonical CBOR.
pub fn value_to_vec(value: &Value) -> Result<Vec<u8>, CanonError> {
    let mut out = Vec::new();
    write(value, &mut out)?;
    Ok(out)
}

/// The half-precision bits of `v` if `v` is exactly a half-precision value (or +-0, +-Infinity), else `None`. NaN is `None`: it has one form, `f97e00`.
pub fn f16_bits_exact(v: f64) -> Option<u16> {
    if v.is_nan() {
        return None;
    }
    if v == 0.0 {
        return Some(if v.is_sign_negative() { 0x8000 } else { 0 });
    }
    if v.is_infinite() {
        return Some(if v > 0.0 { 0x7c00 } else { 0xfc00 });
    }
    let sign: u16 = if v < 0.0 { 0x8000 } else { 0 };
    let a = v.abs();
    if a > 65504.0 {
        return None;
    }
    if a < 2f64.powi(-14) {
        // subnormal: a multiple of 2^-24 below 2^-14
        let m = a * 2f64.powi(24);
        return if m.fract() == 0.0 {
            Some(sign | m as u16)
        } else {
            None
        };
    }
    let bits = a.to_bits();
    if bits & ((1u64 << 42) - 1) != 0 {
        return None; // more than 10 mantissa bits
    }
    let exp = ((bits >> 52) & 0x7ff) as i32 - 1023; // -14 ..= 15
    let mant = ((bits >> 42) & 0x3ff) as u16;
    Some(sign | (((exp + 15) as u16) << 10) | mant)
}

/// The half-precision value of the bits `h` (NaN for every NaN pattern).
pub fn f16_to_f64(h: u16) -> f64 {
    let sign = if h & 0x8000 != 0 { -1.0 } else { 1.0 };
    let exp = ((h >> 10) & 0x1f) as i32;
    let mant = (h & 0x3ff) as f64;
    match exp {
        0 => sign * mant * 2f64.powi(-24),
        31 if mant == 0.0 => sign * f64::INFINITY,
        31 => f64::NAN,
        _ => sign * (1.0 + mant / 1024.0) * 2f64.powi(exp - 15),
    }
}

fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n < 0x100 {
        out.extend_from_slice(&[m | 24, n as u8]);
    } else if n < 0x1_0000 {
        out.push(m | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n < 0x1_0000_0000 {
        out.push(m | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

fn float(out: &mut Vec<u8>, f: f64) {
    if f.is_nan() {
        out.extend_from_slice(&[0xf9, 0x7e, 0x00]);
    } else if let Some(h) = f16_bits_exact(f) {
        out.push(0xf9);
        out.extend_from_slice(&h.to_be_bytes());
    } else if (f as f32) as f64 == f {
        out.push(0xfa);
        out.extend_from_slice(&(f as f32).to_be_bytes());
    } else {
        out.push(0xfb);
        out.extend_from_slice(&f.to_be_bytes());
    }
}

fn write(value: &Value, out: &mut Vec<u8>) -> Result<(), CanonError> {
    match value {
        Value::Integer(i) => {
            let n = i128::from(*i);
            if n >= 0 {
                head(out, 0, n as u64);
            } else {
                head(out, 1, (-1 - n) as u64);
            }
        }
        Value::Bytes(b) => {
            head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Float(f) => float(out, *f),
        Value::Text(t) => {
            head(out, 3, t.len() as u64);
            out.extend_from_slice(t.as_bytes());
        }
        Value::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
        Value::Null => out.push(0xf6),
        Value::Array(items) => {
            head(out, 4, items.len() as u64);
            for item in items {
                write(item, out)?;
            }
        }
        Value::Map(entries) => {
            head(out, 5, entries.len() as u64);
            let mut encoded = Vec::with_capacity(entries.len());
            for (k, v) in entries {
                let mut key = Vec::new();
                write(k, &mut key)?;
                encoded.push((key, v));
            }
            encoded.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));
            for pair in encoded.windows(2) {
                if pair[0].0 == pair[1].0 {
                    return Err(CanonError("two map keys encode alike".into()));
                }
            }
            for (key, v) in encoded {
                out.extend_from_slice(&key);
                write(v, out)?;
            }
        }
        Value::Tag(..) => return Err(CanonError("tags are not used by the protocol".into())),
        _ => return Err(CanonError("a value this encoder does not know".into())),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    fn hexed<T: Serialize>(v: &T) -> String {
        hex::encode(to_vec(v).unwrap())
    }

    #[derive(Serialize)]
    struct Unsorted {
        zz: u8,
        a: u8,
        type_: u8,
        b: u8,
        aa: u8,
        e: String,
    }

    #[test]
    fn struct_fields_are_written_length_first_then_bytewise_whatever_their_declared_order() {
        let got = hexed(&Unsorted {
            zz: 1,
            a: 2,
            type_: 3,
            b: 4,
            aa: 5,
            e: "x".into(),
        });
        // a, b, e (1 byte), then aa, zz, then type_ (5 bytes)
        let want = "a6".to_string()
            + "6161"
            + "02"
            + "6162"
            + "04"
            + "6165"
            + "6178"
            + "626161"
            + "05"
            + "62"
            + "7a7a"
            + "01"
            + "65"
            + "747970655f"
            + "03";
        assert_eq!(got, want);
    }

    #[test]
    fn keys_are_compared_by_their_utf8_bytes_and_nested_maps_are_sorted_too() {
        let v = Value::Map(vec![
            (Value::Text("\u{1F600}".into()), Value::Integer(1.into())),
            (Value::Text("\u{FFFF}".into()), Value::Integer(2.into())),
            (Value::Text("z".into()), Value::Integer(3.into())),
            (Value::Text("\u{0101}".into()), Value::Integer(4.into())),
            (Value::Text("\u{00DF}".into()), Value::Integer(5.into())),
        ]);
        let got = hex::encode(value_to_vec(&v).unwrap());
        assert_eq!(
            got,
            "a5".to_string()
                + "617a"
                + "03"
                + "62c39f"
                + "05"
                + "62c481"
                + "04"
                + "63efbfbf"
                + "02"
                + "64f09f9880"
                + "01"
        );
        let nested = Value::Map(vec![
            (
                Value::Text("y".into()),
                Value::Map(vec![
                    (Value::Text("b".into()), Value::Integer(1.into())),
                    (Value::Text("a".into()), Value::Integer(2.into())),
                ]),
            ),
            (
                Value::Text("x".into()),
                Value::Array(vec![Value::Map(vec![
                    (Value::Text("d".into()), Value::Integer(1.into())),
                    (Value::Text("c".into()), Value::Integer(2.into())),
                ])]),
            ),
        ]);
        assert_eq!(
            hex::encode(value_to_vec(&nested).unwrap()),
            "a2".to_string()
                + "6178"
                + "81"
                + "a2"
                + "6163"
                + "02"
                + "6164"
                + "01"
                + "6179"
                + "a2"
                + "6161"
                + "02"
                + "6162"
                + "01"
        );
    }

    #[test]
    fn integer_like_text_keys_are_sorted_as_bytes() {
        let v = Value::Map(vec![
            (Value::Text("b".into()), Value::Integer(1.into())),
            (Value::Text("10".into()), Value::Integer(2.into())),
            (Value::Text("2".into()), Value::Integer(3.into())),
        ]);
        assert_eq!(
            hex::encode(value_to_vec(&v).unwrap()),
            "a3".to_string() + "6132" + "03" + "6162" + "01" + "623130" + "02"
        );
    }

    #[test]
    fn two_keys_that_encode_alike_are_an_error() {
        let v = Value::Map(vec![
            (Value::Text("a".into()), Value::Null),
            (Value::Text("a".into()), Value::Null),
        ]);
        assert!(value_to_vec(&v).is_err());
    }

    /// The same table as `test/cbor-canonical.test.mjs` ("canonical encoding: floats and integers"): both encoders write these bytes.
    #[test]
    fn floats_are_the_shortest_width_that_reads_back_exactly() {
        let cases: &[(f64, &str)] = &[
            (1.5, "f93e00"),
            (0.5, "f93800"),
            (-4.1, "fbc010666666666666"),
            (1.1, "fb3ff199999999999a"),
            (1e300, "fb7e37e43c8800759c"),
            (5.5, "f94580"),
            (5.960464477539063e-8, "f90001"),
            (0.00006103515625, "f90400"),
            (3.4028234663852886e38, "fa7f7fffff"),
            (1.00048828125, "fa3f801000"),
            (18446744073709551616.0, "fa5f800000"),
            (f64::INFINITY, "f97c00"),
            (f64::NEG_INFINITY, "f9fc00"),
            (f64::NAN, "f97e00"),
            (-0.0, "f98000"),
            (0.0, "f90000"),
            (65504.0, "f97bff"),
        ];
        for (f, want) in cases {
            assert_eq!(&hexed(f), want, "{f}");
        }
        assert!(
            hexed(&65504.5f64).starts_with("fa"),
            "above the half range, in the single range"
        );
        // a NaN with a payload or the sign set is the one NaN
        for bits in [
            0x7ff8_0000_0000_0001u64,
            0xfff8_0000_0000_0000,
            0x7ff0_0000_0000_0001,
        ] {
            assert_eq!(hexed(&f64::from_bits(bits)), "f97e00", "{bits:x}");
        }
        assert_eq!(hexed(&f32::NAN), "f97e00");
        assert_eq!(hexed(&0.1f32), "fa3dcccccd");
    }

    #[test]
    fn every_half_precision_value_is_written_as_half_and_nothing_wider_is_ever_needed() {
        let mut checked = 0;
        for h in 0u32..0x1_0000 {
            let h = h as u16;
            let v = f16_to_f64(h);
            if v.is_nan() {
                continue;
            }
            assert_eq!(f16_bits_exact(v), Some(h), "{h:04x}");
            assert_eq!(hexed(&v), format!("f9{h:04x}"), "{h:04x}");
            checked += 1;
        }
        assert_eq!(checked, 0x1_0000 - 2046);
    }

    #[test]
    fn a_value_between_half_values_is_not_a_half() {
        for h in 0u16..0x7bff {
            let (a, b) = (f16_to_f64(h), f16_to_f64(h + 1));
            let mid = (a + b) / 2.0;
            if mid != a && mid != b {
                assert_eq!(f16_bits_exact(mid), None, "{h:04x}");
            }
        }
        assert_eq!(f16_bits_exact(65520.0), None);
        assert_eq!(f16_bits_exact(1e-8), None);
        assert_eq!(f16_bits_exact(f64::NAN), None);
    }

    #[test]
    fn integers_are_the_shortest_head_across_the_whole_64_bit_range() {
        assert_eq!(hexed(&0u8), "00");
        assert_eq!(hexed(&23u8), "17");
        assert_eq!(hexed(&24u8), "1818");
        assert_eq!(hexed(&256u16), "190100");
        assert_eq!(hexed(&65536u32), "1a00010000");
        assert_eq!(hexed(&4294967296u64), "1b0000000100000000");
        assert_eq!(hexed(&(1u64 << 53)), "1b0020000000000000");
        assert_eq!(hexed(&u64::MAX), "1bffffffffffffffff");
        assert_eq!(hexed(&-1i64), "20");
        assert_eq!(hexed(&-25i64), "3818");
        assert_eq!(hexed(&i64::MIN), "3b7fffffffffffffff");
        assert_eq!(hexed(&-(1i128 << 64)), "3bffffffffffffffff");
    }

    #[test]
    fn scalars_strings_bytes_and_containers() {
        assert_eq!(hexed(&true), "f5");
        assert_eq!(hexed(&false), "f4");
        assert_eq!(hexed(&Option::<u8>::None), "f6");
        assert_eq!(hexed(&"é世"), "65c3a9e4b896");
        assert_eq!(hexed(&"a".repeat(24)), format!("7818{}", "61".repeat(24)));
        assert_eq!(hexed(&Vec::<u8>::new()), "80");
        assert_eq!(hexed(&serde_json::json!({})), "a0");
        assert_eq!(
            hex::encode(value_to_vec(&Value::Bytes(vec![1, 2, 3])).unwrap()),
            "43010203"
        );
        assert!(value_to_vec(&Value::Tag(1, Box::new(Value::Null))).is_err());
    }

    #[test]
    fn what_is_written_is_accepted_by_the_strict_decoder_and_is_a_fixed_point() {
        let msg = serde_json::json!({"z": [1, 2.5, {"b": null, "a": -3}], "a": "x", "mm": 1e300, "n": f64::MAX});
        let bytes = to_vec(&msg).unwrap();
        crate::cbor_strict::validate_with(&bytes, &crate::cbor_strict::Options::strict()).unwrap();
        let tree: Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(value_to_vec(&tree).unwrap(), bytes);
    }

    /// Both encoders and both decoders, over every vector the JS encoder (`js`) and this encoder (`rust`) wrote: the bytes are canonical, which is
    /// the same as saying a decode and a canonical re-encode gives them back.
    #[test]
    fn the_golden_vectors_are_canonical_and_the_legacy_ones_re_encode_to_them() {
        let doc: serde_json::Value =
            serde_json::from_str(include_str!("../../../spec/cbor-vectors.json")).unwrap();
        let mut n = 0;
        for vec in doc["vectors"].as_array().unwrap() {
            let name = vec["name"].as_str().unwrap();
            let canon_of = |side: &str| -> Vec<u8> {
                let bytes = hex::decode(
                    vec[side]
                        .as_str()
                        .unwrap_or_else(|| panic!("{name}: no {side}")),
                )
                .unwrap();
                let tree: Value = ciborium::from_reader(bytes.as_slice()).unwrap();
                value_to_vec(&tree).unwrap()
            };
            for side in ["js", "rust"] {
                let bytes = hex::decode(vec[side].as_str().unwrap()).unwrap();
                assert_eq!(
                    canon_of(side),
                    bytes,
                    "{name}/{}: {side} is not canonical",
                    vec["kind"]
                );
                crate::cbor_strict::validate_with(&bytes, &crate::cbor_strict::Options::strict())
                    .unwrap_or_else(|e| panic!("{name}/{side}: {e}"));
                n += 1;
            }
            // what the released encoders wrote re-encodes to what this one writes: JS from `js_released`, Rust from `rust_released`
            assert_eq!(
                canon_of("js_released"),
                hex::decode(vec["js"].as_str().unwrap()).unwrap(),
                "{name}: js_released"
            );
            let released_rust = canon_of("rust_released");
            let current_rust = hex::decode(vec["rust"].as_str().unwrap()).unwrap();
            assert_eq!(released_rust, current_rust, "{name}: rust_released");
        }
        assert!(n >= 400, "{n}");
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct IntField {
        n: u64,
    }
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct FloatField {
        x: f64,
    }

    /// Filled in from what ciborium does (see the test below).
    const INT_IN_FLOAT_FIELD_IS_READ: bool = false;

    /// #325 item 5, the Rust half: the typed decoder keeps the integer/float split that the JS decoder cannot. `f93c00` is 1.0 and `01` is 1, JS
    /// reads both as the number 1; here an integer field refuses the float. This cannot change without breaking the released peers that write
    /// an `f64` field as a float, so it is documented rather than removed.
    #[test]
    fn float_is_not_integer_in_typed_decode() {
        let f1 = hex::decode("a1616ef93c00").unwrap(); // {"n": 1.0}
        let i1 = hex::decode("a1616e01").unwrap(); // {"n": 1}
        assert!(
            crate::codec::cbor_decode::<IntField>(&f1).is_err(),
            "an integer field refuses a float"
        );
        assert_eq!(
            crate::codec::cbor_decode::<IntField>(&i1).unwrap(),
            IntField { n: 1 }
        );
        let fx = hex::decode("a16178f93c00").unwrap(); // {"x": 1.0}
        let ix = hex::decode("a1617801").unwrap(); // {"x": 1}
        assert_eq!(
            crate::codec::cbor_decode::<FloatField>(&fx).unwrap(),
            FloatField { x: 1.0 }
        );
        // whether a float field takes an integer is ciborium's rule; pin it so a dependency bump that changes it is noticed
        let int_in_float_field = crate::codec::cbor_decode::<FloatField>(&ix);
        assert_eq!(
            int_in_float_field.is_ok(),
            INT_IN_FLOAT_FIELD_IS_READ,
            "{int_in_float_field:?}"
        );
        // the encoder writes a float for a float field and an integer for an integer field
        assert_eq!(hexed(&FloatField { x: 1.0 }), "a16178f93c00");
        assert_eq!(hexed(&IntField { n: 1 }), "a1616e01");
    }
}
