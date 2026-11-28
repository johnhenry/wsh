//! Deserializers for the spec's `f64` fields (`Metrics.cpu`, `CopilotSuggest.confidence`, `NodeAnnounce.load`; generated into
//! `messages.gen.rs` by `spec/codegen.mjs`).
//!
//! A JS peer has one number type and writes an integral value as a CBOR integer (`cpu: 1` is `01`, never `f93c00`; the JS decoder cannot tell the
//! two apart), so an `f64` field must take an integer item as well as a float one (#335). Serde's own `f64` impl refuses an integer, so these read
//! "any number". They are used for those fields only: an integer is still refused in a field that is not `f64`, and a float in an integer field.
//! A float is read as it always was (the canonical width rules are the strict check's, [`crate::cbor_strict`]); an integer is the nearest `f64`.

use serde::de::{self, Deserializer, Visitor};
use std::fmt;

struct Number;

impl<'de> Visitor<'de> for Number {
    type Value = f64;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a number")
    }
    fn visit_f32<E: de::Error>(self, v: f32) -> Result<f64, E> {
        Ok(f64::from(v))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<f64, E> {
        Ok(v)
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<f64, E> {
        Ok(v as f64)
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<f64, E> {
        Ok(v as f64)
    }
    fn visit_i128<E: de::Error>(self, v: i128) -> Result<f64, E> {
        Ok(v as f64)
    }
    fn visit_u128<E: de::Error>(self, v: u128) -> Result<f64, E> {
        Ok(v as f64)
    }
}

struct OptionNumber;

impl<'de> Visitor<'de> for OptionNumber {
    type Value = Option<f64>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a number or null")
    }
    fn visit_none<E: de::Error>(self) -> Result<Option<f64>, E> {
        Ok(None)
    }
    fn visit_unit<E: de::Error>(self) -> Result<Option<f64>, E> {
        Ok(None)
    }
    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Option<f64>, D::Error> {
        number(d).map(Some)
    }
}

/// `#[serde(deserialize_with = "crate::f64_field::number")]`: a required `f64`, from a float or an integer item.
pub fn number<'de, D: Deserializer<'de>>(d: D) -> Result<f64, D::Error> {
    d.deserialize_any(Number)
}

/// `#[serde(deserialize_with = "crate::f64_field::option_number")]`: an optional `f64`, from a float or an integer item (or null).
pub fn option_number<'de, D: Deserializer<'de>>(d: D) -> Result<Option<f64>, D::Error> {
    d.deserialize_option(OptionNumber)
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Req {
        #[serde(deserialize_with = "super::number")]
        v: f64,
    }

    #[derive(Debug, Deserialize)]
    struct Opt {
        #[serde(default, deserialize_with = "super::option_number")]
        v: Option<f64>,
    }

    fn dec<T: serde::de::DeserializeOwned>(hex_str: &str) -> Result<T, String> {
        let bytes = hex::decode(hex_str).unwrap();
        ciborium::from_reader(bytes.as_slice()).map_err(|e| e.to_string())
    }

    // {"v": <item>}
    fn req(item: &str) -> Result<f64, String> {
        dec::<Req>(&format!("a16176{item}")).map(|r| r.v)
    }
    fn opt(item: &str) -> Result<Option<f64>, String> {
        dec::<Opt>(&format!("a16176{item}")).map(|r| r.v)
    }

    #[test]
    fn integers_and_every_float_width() {
        assert_eq!(req("01"), Ok(1.0));
        assert_eq!(req("00"), Ok(0.0));
        assert_eq!(req("20"), Ok(-1.0));
        assert_eq!(req("1864"), Ok(100.0));
        assert_eq!(req("1b0000000100000000"), Ok(4294967296.0));
        assert_eq!(req("f93c00"), Ok(1.0));
        assert_eq!(req("fa3fc00000"), Ok(1.5));
        assert_eq!(req("fb3ff8000000000000"), Ok(1.5));
        assert_eq!(opt("01"), Ok(Some(1.0)));
        assert_eq!(opt("f93800"), Ok(Some(0.5)));
        assert_eq!(opt("f6"), Ok(None));
        assert_eq!(dec::<Opt>("a0").unwrap().v, None);
    }

    #[test]
    fn everything_else_is_refused() {
        for item in ["6131", "f5", "f6", "80", "4101", "a0"] {
            assert!(req(item).is_err(), "{item}");
        }
        for item in ["6131", "f5", "80", "4101", "a0"] {
            assert!(opt(item).is_err(), "{item}");
        }
    }
}
