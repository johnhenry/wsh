//! The destination-address classifier of the gateway: what kind of address is this IP, and is it
//! global unicast (the only kind a gateway dials without a rule naming it)?
//!
//! This is the same classifier as `src/address-class.mjs` (the Node host's
//! `@johnhenry/wsh/address-guard`), and both run `spec/address-class.vectors.json`, so the two
//! agree address by address. "Public" means globally routable unicast; every other address has a
//! class of its own so a refusal can say why. An IPv6 address that merely wraps an IPv4 one is
//! classified as the IPv4 address it wraps, because that is where a translator or tunnel would send
//! the packet: an IPv4-mapped address (`::ffff:127.0.0.1`), a NAT64 address (`64:ff9b::7f00:1`) and
//! a 6to4 address (`2002:7f00:1::`). A Teredo address (`2001::/32`) hides its server and client
//! addresses behind an obfuscation and is refused whatever it wraps. The deprecated
//! IPv4-compatible form (`::127.0.0.1`) is `reserved`, and so is the local-use NAT64 prefix
//! (`64:ff9b:1::/48`). Only `2000::/3` is global unicast in IPv6.

use std::fmt;
use std::net::{IpAddr, Ipv6Addr};

/// What kind of address an IP is. [`AddressClass::Public`] is the only class dialled without a
/// rule; the others say why an address was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressClass {
    /// Globally routable unicast.
    Public,
    /// Not an address at all (only [`classify_address_str`] returns it).
    Invalid,
    /// `0.0.0.0/8`, `::`.
    Unspecified,
    /// `127.0.0.0/8`, `::1`.
    Loopback,
    /// RFC 1918 and the deprecated IPv6 site-local block `fec0::/10`.
    Private,
    /// `fc00::/7`.
    UniqueLocal,
    /// `169.254.0.0/16`, `fe80::/10`.
    LinkLocal,
    /// A cloud instance-metadata or platform endpoint.
    Metadata,
    /// `100.64.0.0/10`.
    CarrierNat,
    /// The documentation ranges.
    Documentation,
    /// The benchmarking ranges.
    Benchmarking,
    /// `224.0.0.0/4`, `ff00::/8`.
    Multicast,
    /// `2001::/32`.
    Teredo,
    /// Everything else that is not global unicast.
    Reserved,
}

impl AddressClass {
    /// Every class, in the order of the vectors file and of `ADDRESS_CLASSES` in the Node host.
    pub const ALL: [AddressClass; 14] = [
        AddressClass::Public,
        AddressClass::Invalid,
        AddressClass::Unspecified,
        AddressClass::Loopback,
        AddressClass::Private,
        AddressClass::UniqueLocal,
        AddressClass::LinkLocal,
        AddressClass::Metadata,
        AddressClass::CarrierNat,
        AddressClass::Documentation,
        AddressClass::Benchmarking,
        AddressClass::Multicast,
        AddressClass::Teredo,
        AddressClass::Reserved,
    ];

    /// The class name, the same word the Node host uses (`"public"`, `"unique-local"`, ...).
    pub fn as_str(self) -> &'static str {
        match self {
            AddressClass::Public => "public",
            AddressClass::Invalid => "invalid",
            AddressClass::Unspecified => "unspecified",
            AddressClass::Loopback => "loopback",
            AddressClass::Private => "private",
            AddressClass::UniqueLocal => "unique-local",
            AddressClass::LinkLocal => "link-local",
            AddressClass::Metadata => "metadata",
            AddressClass::CarrierNat => "carrier-nat",
            AddressClass::Documentation => "documentation",
            AddressClass::Benchmarking => "benchmarking",
            AddressClass::Multicast => "multicast",
            AddressClass::Teredo => "teredo",
            AddressClass::Reserved => "reserved",
        }
    }
}

impl fmt::Display for AddressClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `[address, prefix bits, class]`, first match wins: the single addresses of cloud metadata
/// services come before their blocks.
const V4_RULES: [([u8; 4], u32, AddressClass); 20] = [
    ([169, 254, 169, 254], 32, AddressClass::Metadata), // AWS, GCP, Azure, DigitalOcean, OpenStack
    ([169, 254, 170, 2], 32, AddressClass::Metadata),   // AWS ECS task metadata
    ([100, 100, 100, 200], 32, AddressClass::Metadata), // Alibaba Cloud
    ([192, 0, 0, 192], 32, AddressClass::Metadata),     // Oracle Cloud
    ([168, 63, 129, 16], 32, AddressClass::Metadata),   // Azure's platform endpoint
    ([0, 0, 0, 0], 8, AddressClass::Unspecified),
    ([10, 0, 0, 0], 8, AddressClass::Private),
    ([100, 64, 0, 0], 10, AddressClass::CarrierNat),
    ([127, 0, 0, 0], 8, AddressClass::Loopback),
    ([169, 254, 0, 0], 16, AddressClass::LinkLocal),
    ([172, 16, 0, 0], 12, AddressClass::Private),
    ([192, 0, 0, 0], 24, AddressClass::Reserved),
    ([192, 0, 2, 0], 24, AddressClass::Documentation),
    ([192, 88, 99, 0], 24, AddressClass::Reserved),
    ([192, 168, 0, 0], 16, AddressClass::Private),
    ([198, 18, 0, 0], 15, AddressClass::Benchmarking),
    ([198, 51, 100, 0], 24, AddressClass::Documentation),
    ([203, 0, 113, 0], 24, AddressClass::Documentation),
    ([224, 0, 0, 0], 4, AddressClass::Multicast),
    ([240, 0, 0, 0], 4, AddressClass::Reserved),
];

/// Do the first `bits` bits of `a` and `b` agree?
fn same_v4_prefix(a: [u8; 4], b: [u8; 4], bits: u32) -> bool {
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    u32::from_be_bytes(a) & mask == u32::from_be_bytes(b) & mask
}

fn v4_class(o: [u8; 4]) -> AddressClass {
    for (net, bits, class) in V4_RULES {
        if same_v4_prefix(o, net, bits) {
            return class;
        }
    }
    AddressClass::Public
}

fn all_zero(b: &[u8]) -> bool {
    b.iter().all(|&x| x == 0)
}

/// The IPv4 address an IPv6 one wraps (mapped, NAT64, 6to4), or `None` if it wraps none.
fn embedded_v4(b: &[u8; 16]) -> Option<[u8; 4]> {
    let tail = |from: usize| [b[from], b[from + 1], b[from + 2], b[from + 3]];
    if all_zero(&b[0..10]) && b[10] == 0xff && b[11] == 0xff {
        return Some(tail(12)); // ::ffff:a.b.c.d
    }
    if b[0] == 0 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b && all_zero(&b[4..12]) {
        return Some(tail(12)); // 64:ff9b::/96
    }
    if b[0] == 0x20 && b[1] == 0x02 {
        return Some(tail(2)); // 2002::/16 (6to4)
    }
    None
}

fn v6_class(ip: Ipv6Addr) -> AddressClass {
    let b = ip.octets();
    if let Some(inner) = embedded_v4(&b) {
        return v4_class(inner);
    }
    if all_zero(&b[0..12]) {
        // ::/96: unspecified, loopback, the deprecated IPv4-compatible form
        if all_zero(&b[12..16]) {
            return AddressClass::Unspecified;
        }
        return if all_zero(&b[12..15]) && b[15] == 1 {
            AddressClass::Loopback
        } else {
            AddressClass::Reserved
        };
    }
    // fd00:ec2::254, AWS over IPv6
    if b[0] == 0xfd
        && b[1] == 0x00
        && b[2] == 0x0e
        && b[3] == 0xc2
        && all_zero(&b[4..14])
        && b[14] == 0x02
        && b[15] == 0x54
    {
        return AddressClass::Metadata;
    }
    if b[0] & 0xfe == 0xfc {
        return AddressClass::UniqueLocal; // fc00::/7
    }
    if b[0] == 0xfe && b[1] & 0xc0 == 0x80 {
        return AddressClass::LinkLocal; // fe80::/10
    }
    if b[0] == 0xfe && b[1] & 0xc0 == 0xc0 {
        return AddressClass::Private; // fec0::/10, the deprecated site-local block
    }
    if b[0] == 0xff {
        return AddressClass::Multicast;
    }
    if b[0] & 0xe0 != 0x20 {
        return AddressClass::Reserved; // only 2000::/3 is global unicast
    }
    if b[0] == 0x20 && b[1] == 0x01 {
        if b[2] == 0 && b[3] == 0 {
            return AddressClass::Teredo; // 2001::/32
        }
        if b[2] == 0 && b[3] == 2 && b[4] == 0 && b[5] == 0 {
            return AddressClass::Benchmarking; // 2001:2::/48
        }
        if b[2] <= 0x01 {
            return AddressClass::Reserved; // 2001::/23: IETF protocol assignments, ORCHID, ...
        }
        if b[2] == 0x0d && b[3] == 0xb8 {
            return AddressClass::Documentation; // 2001:db8::/32
        }
    }
    if b[0] == 0x3f && b[1] == 0xff && b[2] & 0xf0 == 0 {
        return AddressClass::Documentation; // 3fff::/20
    }
    AddressClass::Public
}

/// What kind of address is `ip`? [`AddressClass::Public`], or the reason it is not. Never
/// [`AddressClass::Invalid`]: a value of type `IpAddr` is an address.
pub fn classify_address(ip: IpAddr) -> AddressClass {
    match ip {
        IpAddr::V4(a) => v4_class(a.octets()),
        IpAddr::V6(a) => v6_class(a),
    }
}

/// [`classify_address`] for text: anything that is not an IP address is
/// [`AddressClass::Invalid`].
#[allow(dead_code)] // the counterpart of `classifyAddress(text)`; the gateway holds parsed addresses
pub fn classify_address_str(text: &str) -> AddressClass {
    text.parse::<IpAddr>()
        .map_or(AddressClass::Invalid, classify_address)
}

/// Is this address globally routable unicast, wrapped forms included?
#[allow(dead_code)] // the counterpart of `isPublicAddress`; the policy uses `is_restricted_address`
pub fn is_public_address(ip: IpAddr) -> bool {
    classify_address(ip) == AddressClass::Public
}

/// The distinct class names of `addrs`, in the order first seen, joined with commas: what a
/// refusal log says about the addresses a name resolved to.
pub fn describe_classes(addrs: &[IpAddr]) -> String {
    let mut seen: Vec<AddressClass> = Vec::new();
    for &ip in addrs {
        let class = classify_address(ip);
        if !seen.contains(&class) {
            seen.push(class);
        }
    }
    seen.iter()
        .map(|c| c.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The vectors the Node host runs too (`test/address-guard-export.test.mjs`).
    const VECTORS: &str = include_str!("../../../../spec/address-class.vectors.json");

    fn vectors() -> serde_json::Value {
        serde_json::from_str(VECTORS).expect("the vectors file is JSON")
    }

    #[test]
    fn the_vectors_file_names_exactly_the_classes_this_implementation_has() {
        let v = vectors();
        assert_eq!(v["version"], 1);
        let named: Vec<&str> = v["classes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap())
            .collect();
        let ours: Vec<&str> = AddressClass::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(named, ours);
    }

    #[test]
    fn every_vector_has_its_class_and_its_public_flag() {
        let v = vectors();
        let mut failed = Vec::new();
        let mut seen = Vec::new();
        let mut count = 0;
        for group in v["groups"].as_array().unwrap() {
            for vector in group["vectors"].as_array().unwrap() {
                count += 1;
                let address = vector["address"].as_str().unwrap();
                let class = vector["class"].as_str().unwrap();
                let public = vector["public"].as_bool().unwrap();
                assert_eq!(
                    public,
                    class == "public",
                    "{address}: the file contradicts itself"
                );
                let got = classify_address_str(address);
                seen.push(class.to_string());
                if got.as_str() != class {
                    failed.push(format!("{address}: expected {class}, got {got}"));
                }
                let is_public = address
                    .parse::<IpAddr>()
                    .map(is_public_address)
                    .unwrap_or(false);
                if is_public != public {
                    failed.push(format!("{address}: expected public={public}"));
                }
            }
        }
        assert!(count > 200, "the vectors file is read ({count} vectors)");
        assert!(failed.is_empty(), "{} failed: {failed:#?}", failed.len());
        for class in AddressClass::ALL {
            assert!(
                seen.iter().any(|s| s == class.as_str()),
                "no vector for {class}"
            );
        }
    }

    #[test]
    fn describe_classes_lists_each_class_once() {
        let ips: Vec<IpAddr> = ["10.0.0.1", "10.0.0.2", "8.8.8.8", "2002:a9fe:a9fe::1"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(describe_classes(&ips), "private,public,metadata");
        assert_eq!(describe_classes(&[]), "");
    }
}
