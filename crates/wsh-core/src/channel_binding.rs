//! Channel binding for the Auth transcript (wsh #119, #145). Byte-compatible with
//! `src/channel-binding.mjs`; the layout and test vectors are in `spec/wsh-v1.yaml` (Auth).
//!
//! `binding = SHA-256("wsh-channel-binding-v1\0" || for each present kind, in the order of
//! [`KINDS`]: lp(kind) || lp(value))`, or the EMPTY byte string when no kind is present --
//! exactly the transcript released peers sign. Negotiated by feature strings only:
//! `channel-binding:<kind>` (a host that can bind the kind) and `channel-binding-required`.

use sha2::{Digest, Sha256};

pub const CHANNEL_BINDING_PREFIX: &str = "channel-binding:";
pub const CHANNEL_BINDING_REQUIRED_FEATURE: &str = "channel-binding-required";
/// Canonical order of the kinds inside the hash.
pub const KINDS: [&str; 3] = ["cert-hash", "host", "tls-exporter"];
const LABEL: &[u8] = b"wsh-channel-binding-v1\0";

fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The binding over `values` (`(kind, value)`); unknown kinds and empty values are ignored.
/// Empty when no kind is present.
pub fn compute(values: &[(&str, &[u8])]) -> Vec<u8> {
    let mut data = LABEL.to_vec();
    let mut any = false;
    for kind in KINDS {
        if let Some((_, v)) = values.iter().find(|(k, v)| *k == kind && !v.is_empty()) {
            lp(&mut data, kind.as_bytes());
            lp(&mut data, v);
            any = true;
        }
    }
    if any {
        Sha256::digest(&data).to_vec()
    } else {
        Vec::new()
    }
}

/// The kinds a `ServerHello.features` list offers, in canonical order.
pub fn offered_kinds(features: &[String]) -> Vec<&'static str> {
    KINDS
        .into_iter()
        .filter(|k| {
            features
                .iter()
                .any(|f| f.strip_prefix(CHANNEL_BINDING_PREFIX) == Some(k))
        })
        .collect()
}

/// Does `features` say the host requires a channel binding?
pub fn requires_binding(features: &[String]) -> bool {
    features
        .iter()
        .any(|f| f == CHANNEL_BINDING_REQUIRED_FEATURE)
}

/// The `ServerHello` feature strings for what a host can bind.
pub fn binding_features(kinds: &[&str], required: bool) -> Vec<String> {
    let mut out: Vec<String> = kinds
        .iter()
        .map(|k| format!("{CHANNEL_BINDING_PREFIX}{k}"))
        .collect();
    if required {
        out.push(CHANNEL_BINDING_REQUIRED_FEATURE.to_string());
    }
    out
}

/// The client side: bind every kind the host offers that this client can supply.
/// Returns `(binding, kinds bound)`.
pub fn client_binding(
    server_features: &[String],
    available: &[(&'static str, Vec<u8>)],
) -> (Vec<u8>, Vec<&'static str>) {
    let kinds: Vec<&'static str> = offered_kinds(server_features)
        .into_iter()
        .filter(|k| available.iter().any(|(a, v)| a == k && !v.is_empty()))
        .collect();
    let values: Vec<(&str, &[u8])> = kinds
        .iter()
        .filter_map(|k| {
            available
                .iter()
                .find(|(a, _)| a == k)
                .map(|(a, v)| (*a, v.as_slice()))
        })
        .collect();
    (compute(&values), kinds)
}

/// The host side: every binding a client might legitimately have signed.
///
/// `held`: the kinds this host can compute, each with its value(s) (several for `cert-hash`
/// while a certificate rotates). `required`: `None` accepts the empty binding too;
/// `Some(kinds)` requires a non-empty one that also covers `kinds`.
pub fn acceptable_bindings(
    held: &[(&'static str, Vec<Vec<u8>>)],
    required: Option<&[&str]>,
) -> Vec<Vec<u8>> {
    let kinds: Vec<&(&'static str, Vec<Vec<u8>>)> = KINDS
        .iter()
        .filter_map(|k| held.iter().find(|(h, v)| h == k && !v.is_empty()))
        .collect();
    let must = required.unwrap_or(&[]);
    let mut out = Vec::new();
    for mask in 0..(1u32 << kinds.len()) {
        let subset: Vec<&&(&str, Vec<Vec<u8>>)> = kinds
            .iter()
            .enumerate()
            .filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, k)| k)
            .collect();
        if subset.is_empty() && required.is_some() {
            continue;
        }
        if !must.iter().all(|m| subset.iter().any(|(k, _)| k == m)) {
            continue;
        }
        // Expand alternatives (a rotating certificate has two hashes).
        let mut combos: Vec<Vec<(&str, &[u8])>> = vec![Vec::new()];
        for (kind, values) in subset.iter().map(|s| (&s.0, &s.1)) {
            combos = combos
                .into_iter()
                .flat_map(|c| {
                    values.iter().map(move |v| {
                        let mut n = c.clone();
                        n.push((*kind, v.as_slice()));
                        n
                    })
                })
                .collect();
        }
        for values in combos {
            out.push(compute(&values));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTOR_HOST: &str = "266d39f1ffe60713ab836382fa8373407c8facaa88a3ddaf80c1cd5433e80dcc";
    const VECTOR_ALL: &str = "dc2256bcbd4bff249870321a14390d305147a1e4e6dc701c0a3fc3dfff750da7";

    #[test]
    fn spec_test_vectors() {
        let (c, h, e) = ([0x11u8; 32], [0x22u8; 32], [0x33u8; 32]);
        assert_eq!(hex::encode(compute(&[("host", &h)])), VECTOR_HOST);
        // given out of order: the canonical order is what is hashed
        assert_eq!(
            hex::encode(compute(&[
                ("tls-exporter", &e),
                ("host", &h),
                ("cert-hash", &c)
            ])),
            VECTOR_ALL
        );
    }

    #[test]
    fn no_kind_is_the_empty_binding() {
        assert!(compute(&[]).is_empty());
        assert!(compute(&[("unknown", &[1u8; 32])]).is_empty());
        assert!(compute(&[("host", &[])]).is_empty());
    }

    #[test]
    fn features_parse_in_canonical_order() {
        let f = binding_features(&["tls-exporter", "host"], true);
        assert_eq!(
            f,
            vec![
                "channel-binding:tls-exporter",
                "channel-binding:host",
                "channel-binding-required"
            ]
        );
        let mut with_noise = f.clone();
        with_noise.push("channel-binding:nonsense".into());
        with_noise.push("e2e".into());
        assert_eq!(offered_kinds(&with_noise), vec!["host", "tls-exporter"]);
        assert!(requires_binding(&f));
        assert!(!requires_binding(&["channel-binding:host".to_string()]));
    }

    #[test]
    fn client_binds_what_is_offered_and_available_and_the_host_accepts_it() {
        let offered = binding_features(&["host", "tls-exporter"], false);
        let (binding, kinds) = client_binding(
            &offered,
            &[("host", vec![0x22; 32]), ("cert-hash", vec![0x11; 32])],
        );
        assert_eq!(kinds, vec!["host"]);
        assert_eq!(hex::encode(&binding), VECTOR_HOST);
        let held = [
            ("host", vec![vec![0x22; 32]]),
            ("tls-exporter", vec![vec![0x33; 32]]),
        ];
        let acc = acceptable_bindings(&held, None);
        assert_eq!(acc.len(), 4);
        assert!(acc.contains(&binding));
        assert_eq!(acceptable_bindings(&held, Some(&[])).len(), 3);
        assert_eq!(acceptable_bindings(&held, Some(&["tls-exporter"])).len(), 2);
        let rotating = [("cert-hash", vec![vec![0x11; 32], vec![0x44; 32]])];
        assert_eq!(acceptable_bindings(&rotating, Some(&[])).len(), 2);
    }
}
