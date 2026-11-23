//! Per-key capabilities (wsh #122, step two): the grammar of `capabilities="..."` in an `authorized_keys` line, and
//! `expires="<RFC 3339>"`. The Node host (`src/key-options.mjs`) reads the same grammar the same way;
//! `spec/key-options.vectors.json` holds the vectors both suites run.
//!
//! ```text
//! exec  pty  relay  fs:read  fs:write
//! gateway:tcp:<host>:<port>   gateway:udp:<host>:<port>   gateway:listen:tcp:<port>
//! unix:<path>   unix:listen:<path>   endpoint:<name>   mcp:<tool>   target:<name>   rpc:<protocol>
//! ```
//!
//! `<host>` is a name, an IP literal (IPv6 in brackets), `*`, or `*.suffix` (any subdomain, not the apex); `<port>`
//! a number or `*`; `<path>` absolute, exact or `/dir/*` (anything below `/dir`), with no `.` or `..` segment;
//! `<name>` and `<tool>` exact or `*`. A key that has the option is default-deny: it may do only what it names.

use super::permissions::OptionError;

/// A port in a capability: any, or one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortPat {
    Any,
    One(u16),
}

/// A path in a capability: exact, or everything below a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathPat {
    pub path: String,
    pub prefix: bool,
}

/// One parsed capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    Exec,
    Pty,
    Relay,
    FsRead,
    FsWrite,
    Tcp {
        host: String,
        port: PortPat,
    },
    Udp {
        host: String,
        port: PortPat,
    },
    ListenTcp {
        port: PortPat,
    },
    Unix(PathPat),
    ListenUnix(PathPat),
    /// `None` is `*`.
    Endpoint(Option<String>),
    Mcp(Option<String>),
    Target(Option<String>),
    Rpc(String),
}

fn bad(raw: &str, why: &str) -> OptionError {
    OptionError::new("bad-capability", format!("capability {raw:?}: {why}"))
}

fn unknown(raw: &str) -> OptionError {
    OptionError::new("unknown-capability", format!("unknown capability {raw:?}"))
}

fn parse_port(s: &str) -> Option<PortPat> {
    if s == "*" {
        return Some(PortPat::Any);
    }
    let ok = !s.is_empty()
        && s.len() <= 5
        && s.bytes().all(|b| b.is_ascii_digit())
        && !s.starts_with('0');
    if !ok {
        return None;
    }
    match s.parse::<u32>() {
        Ok(n) if (1..=65535).contains(&n) => Some(PortPat::One(n as u16)),
        _ => None,
    }
}

fn is_domain(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || !b[0].is_ascii_alphanumeric() || !b[b.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    b.iter()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

fn parse_host_port(s: &str) -> Option<(String, PortPat)> {
    let (host, port) = if s.starts_with('[') {
        let close = s.find(']')?;
        if s.as_bytes().get(close + 1) != Some(&b':') {
            return None;
        }
        let host = &s[..=close];
        let inner = &host[1..host.len() - 1];
        if inner.is_empty()
            || !inner
                .bytes()
                .all(|c| c.is_ascii_hexdigit() || c == b':' || c == b'.')
        {
            return None;
        }
        (host, &s[close + 2..])
    } else {
        let idx = s.rfind(':')?;
        let host = &s[..idx];
        let domain = host.strip_prefix("*.").unwrap_or(host);
        if host != "*" && !is_domain(domain) {
            return None;
        }
        (host, &s[idx + 1..])
    };
    Some((host.to_ascii_lowercase(), parse_port(port)?))
}

/// True when `path` is absolute with no empty, `.` or `..` segment.
pub fn path_segments_ok(path: &str) -> bool {
    match path.strip_prefix('/') {
        Some(rest) => rest
            .split('/')
            .all(|s| !s.is_empty() && s != "." && s != ".."),
        None => false,
    }
}

fn parse_path_pattern(s: &str) -> Option<PathPat> {
    if s.chars()
        .any(|c| (c as u32) <= 0x20 || c == '\u{7f}' || matches!(c, ',' | '"' | '\'' | '\\'))
    {
        return None;
    }
    if s == "/*" {
        return Some(PathPat {
            path: "/".into(),
            prefix: true,
        });
    }
    if let Some(dir) = s.strip_suffix("/*") {
        return (path_segments_ok(dir) && !dir.contains('*')).then(|| PathPat {
            path: dir.into(),
            prefix: true,
        });
    }
    (path_segments_ok(s) && !s.contains('*')).then(|| PathPat {
        path: s.into(),
        prefix: false,
    })
}

fn name_ok(s: &str, max: usize, extra: &[u8], first_underscore: bool) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > max {
        return false;
    }
    let first = b[0].is_ascii_alphanumeric() || (first_underscore && b[0] == b'_');
    first
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || extra.contains(c))
}

fn name_cap(raw: &str, prefix: &str, star: bool) -> Result<Option<String>, OptionError> {
    let v = &raw[prefix.len()..];
    if star && v == "*" {
        return Ok(None);
    }
    if name_ok(v, 64, b"._-", false) {
        Ok(Some(v.to_string()))
    } else {
        Err(bad(raw, &format!("expected {prefix}<name>")))
    }
}

/// Parse one capability.
pub fn parse_capability(raw: &str) -> Result<Capability, OptionError> {
    if raw.is_empty() {
        return Err(OptionError::new("bad-capability", "empty capability"));
    }
    if raw.chars().any(|c| c.is_whitespace()) {
        return Err(bad(raw, "contains whitespace"));
    }
    match raw {
        "exec" => return Ok(Capability::Exec),
        "pty" => return Ok(Capability::Pty),
        "relay" => return Ok(Capability::Relay),
        "fs:read" => return Ok(Capability::FsRead),
        "fs:write" => return Ok(Capability::FsWrite),
        _ => {}
    }
    if let Some(rest) = raw.strip_prefix("gateway:") {
        for (prefix, udp) in [("tcp:", false), ("udp:", true)] {
            if let Some(hp) = rest.strip_prefix(prefix) {
                let (host, port) = parse_host_port(hp)
                    .ok_or_else(|| bad(raw, "expected gateway:<tcp|udp>:<host>:<port>"))?;
                return Ok(if udp {
                    Capability::Udp { host, port }
                } else {
                    Capability::Tcp { host, port }
                });
            }
        }
        if let Some(p) = rest.strip_prefix("listen:tcp:") {
            let port =
                parse_port(p).ok_or_else(|| bad(raw, "expected gateway:listen:tcp:<port>"))?;
            return Ok(Capability::ListenTcp { port });
        }
        return Err(unknown(raw));
    }
    if let Some(rest) = raw.strip_prefix("unix:") {
        let (listen, path) = match rest.strip_prefix("listen:") {
            Some(p) => (true, p),
            None => (false, rest),
        };
        let pat = parse_path_pattern(path).ok_or_else(|| {
            bad(
                raw,
                "expected an absolute path, exact or ending in /*, without . or ..",
            )
        })?;
        return Ok(if listen {
            Capability::ListenUnix(pat)
        } else {
            Capability::Unix(pat)
        });
    }
    if raw.starts_with("endpoint:") {
        return name_cap(raw, "endpoint:", true).map(Capability::Endpoint);
    }
    if raw.starts_with("target:") {
        return name_cap(raw, "target:", true).map(Capability::Target);
    }
    if let Some(v) = raw.strip_prefix("mcp:") {
        if v == "*" {
            return Ok(Capability::Mcp(None));
        }
        return if name_ok(v, 128, b"_.:-", true) {
            Ok(Capability::Mcp(Some(v.to_string())))
        } else {
            Err(bad(raw, "expected mcp:<tool>"))
        };
    }
    if raw.starts_with("rpc:") {
        return name_cap(raw, "rpc:", false).map(|n| Capability::Rpc(n.unwrap_or_default()));
    }
    Err(unknown(raw))
}

/// Parse a comma-separated capability list (`""` is the empty list: deny-all).
pub fn parse_capability_list(list: &str) -> Result<Vec<Capability>, OptionError> {
    if list.is_empty() {
        return Ok(Vec::new());
    }
    list.split(',').map(parse_capability).collect()
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's `days_from_civil`).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let yy = if m <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468
}

/// An RFC 3339 timestamp (`2030-01-01T00:00:00Z`, `...+01:00`; fractional seconds allowed and dropped; `T` and `Z` upper
/// case; no leap second) as whole epoch seconds. The Node host parses the same way.
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    let digits = |from: usize, n: usize| -> Option<i64> {
        let part = b.get(from..from + n)?;
        if part.iter().all(|c| c.is_ascii_digit()) {
            Some(part.iter().fold(0i64, |a, c| a * 10 + i64::from(c - b'0')))
        } else {
            None
        }
    };
    let at = |i: usize, c: u8| b.get(i) == Some(&c);
    if !(at(4, b'-') && at(7, b'-') && at(10, b'T') && at(13, b':') && at(16, b':')) {
        return None;
    }
    let (y, mo, d) = (digits(0, 4)?, digits(5, 2)?, digits(8, 2)?);
    let (h, mi, se) = (digits(11, 2)?, digits(14, 2)?, digits(17, 2)?);
    let mut i = 19;
    if at(i, b'.') {
        i += 1;
        let start = i;
        while b.get(i).is_some_and(|c| c.is_ascii_digit()) {
            i += 1;
        }
        if i == start {
            return None;
        }
    }
    let offset = if at(i, b'Z') && i + 1 == b.len() {
        0
    } else if (at(i, b'+') || at(i, b'-')) && at(i + 3, b':') && i + 6 == b.len() {
        let (oh, om) = (digits(i + 1, 2)?, digits(i + 4, 2)?);
        if oh > 23 || om > 59 {
            return None;
        }
        (if at(i, b'+') { 1 } else { -1 }) * (oh * 3600 + om * 60)
    } else {
        return None;
    };
    let days_in = [
        31,
        if is_leap(y) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if y < 1970 || !(1..=12).contains(&mo) || d < 1 || d > days_in[(mo - 1) as usize] {
        return None;
    }
    if h > 23 || mi > 59 || se > 59 {
        return None;
    }
    Some(days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se - offset)
}

// ── Matching ────────────────────────────────────────────────────────────────────────────────

fn port_matches(pat: PortPat, port: u16) -> bool {
    pat == PortPat::Any || pat == PortPat::One(port)
}

/// Whether `host` (a request's) matches a capability's lower-cased host pattern.
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    let norm = if h.contains(':') && !h.starts_with('[') {
        format!("[{h}]")
    } else {
        h
    };
    if pattern == "*" {
        return true;
    }
    if pattern.starts_with("*.") {
        let suffix = &pattern[1..];
        return norm.ends_with(suffix) && norm.len() > suffix.len();
    }
    norm == pattern
}

fn path_matches(pat: &PathPat, path: &str) -> bool {
    if !path_segments_ok(path) {
        return false;
    }
    if !pat.prefix {
        return path == pat.path;
    }
    let dir = if pat.path == "/" {
        ""
    } else {
        pat.path.as_str()
    };
    path.starts_with(&format!("{dir}/")) && path.len() > dir.len() + 1
}

fn name_matches(cap: &Option<String>, name: &str) -> bool {
    cap.as_deref().is_none_or(|c| c == name)
}

/// What the capability list `caps` says of a gateway-style request, or the capability a refusal names.
/// Each function returns `Ok(())` or the name of the capability the request needed.
pub struct CapabilitySet<'a>(pub &'a [Capability]);

impl CapabilitySet<'_> {
    pub fn has(&self, f: impl Fn(&Capability) -> bool) -> bool {
        self.0.iter().any(f)
    }
    pub fn tcp(&self, host: &str, port: u16) -> bool {
        self.has(|c| matches!(c, Capability::Tcp { host: h, port: p } if host_matches(h, host) && port_matches(*p, port)))
    }
    pub fn udp(&self, host: &str, port: u16) -> bool {
        self.has(|c| matches!(c, Capability::Udp { host: h, port: p } if host_matches(h, host) && port_matches(*p, port)))
    }
    pub fn dns(&self, name: &str) -> bool {
        self.has(|c| matches!(c, Capability::Tcp { host: h, .. } if host_matches(h, name)))
    }
    pub fn listen_tcp(&self, port: u16) -> bool {
        self.has(|c| matches!(c, Capability::ListenTcp { port: p } if port_matches(*p, port)))
    }
    pub fn unix(&self, path: &str) -> bool {
        self.has(|c| matches!(c, Capability::Unix(p) if path_matches(p, path)))
    }
    pub fn listen_unix(&self, path: &str) -> bool {
        self.has(|c| matches!(c, Capability::ListenUnix(p) if path_matches(p, path)))
    }
    pub fn endpoint(&self, name: &str) -> bool {
        self.has(|c| matches!(c, Capability::Endpoint(n) if name_matches(n, name)))
    }
    pub fn target(&self, name: &str) -> bool {
        self.has(|c| matches!(c, Capability::Target(n) if name_matches(n, name)))
    }
    pub fn mcp_tool(&self, tool: &str) -> bool {
        self.has(|c| matches!(c, Capability::Mcp(n) if name_matches(n, tool)))
    }
    pub fn mcp_any(&self) -> bool {
        self.has(|c| matches!(c, Capability::Mcp(_)))
    }
    pub fn mcp_all(&self) -> bool {
        self.has(|c| matches!(c, Capability::Mcp(None)))
    }
    pub fn rpc(&self, name: &str) -> bool {
        self.has(|c| matches!(c, Capability::Rpc(n) if n == name))
    }
}
