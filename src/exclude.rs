// SPDX-License-Identifier: MIT
//! IP/CIDR exclusion list for direct passthrough.
//!
//! When a redirected connection's original destination IP matches an entry in
//! the exclude list, atproxy connects directly to the destination instead of
//! tunneling through the upstream HTTP proxy. This is useful for:
//!
//! - Local network resources that should be reached directly
//! - Services that block proxy traffic
//! - IP ranges for which the upstream proxy adds unnecessary latency
//!
//! Entries may be plain IP addresses (treated as host routes — `/32` for IPv4,
//! `/128` for IPv6) or CIDR ranges (`a.b.c.d/prefix`, `2001:db8::/32`). Both
//! IPv4 and IPv6 entries are accepted in the same list. Network bits are
//! normalized so `10.0.0.5/24` and `10.0.0.0/24` behave identically.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub struct ExcludeList {
    v4: Vec<CidrV4>,
    v6: Vec<CidrV6>,
}

#[derive(Debug, Clone, Copy)]
struct CidrV4 {
    network: u32,
    mask: u32,
}

#[derive(Debug, Clone, Copy)]
struct CidrV6 {
    network: [u8; 16],
    prefix: u8,
}

impl ExcludeList {
    /// Build an exclude list from a sequence of `IP` or `IP/prefix` strings.
    ///
    /// Empty / whitespace-only entries are silently skipped. Returns the first
    /// invalid entry as `Err` with a human-readable message.
    pub fn from_strs<'a, I>(iter: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for raw in iter {
            let s = raw.trim();
            if s.is_empty() {
                continue;
            }
            match parse_entry(s) {
                Some(ParsedEntry::V4(e)) => v4.push(e),
                Some(ParsedEntry::V6(e)) => v6.push(e),
                None => return Err(format!("invalid IP address or CIDR: '{s}'")),
            }
        }
        Ok(Self { v4, v6 })
    }

    /// Returns `true` if the IP matches any entry in the list.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(a) => self.contains_v4(a),
            IpAddr::V6(a) => self.contains_v6(a),
        }
    }

    fn contains_v4(&self, ip: Ipv4Addr) -> bool {
        let ip_u32 = u32::from(ip);
        self.v4.iter().any(|e| (ip_u32 & e.mask) == e.network)
    }

    fn contains_v6(&self, ip: Ipv6Addr) -> bool {
        let octets = ip.octets();
        self.v6
            .iter()
            .any(|e| masked_eq(&octets, &e.network, e.prefix))
    }

    /// Total number of entries (v4 + v6).
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    /// Returns `true` if the list has no entries (no exclusion applies).
    #[allow(dead_code)] // used in tests
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

enum ParsedEntry {
    V4(CidrV4),
    V6(CidrV6),
}

/// Parse one entry: `a.b.c.d[/p]`, `::1[/p]`, `2001:db8::/32`, etc.
fn parse_entry(s: &str) -> Option<ParsedEntry> {
    let (ip_str, prefix_str) = match s.split_once('/') {
        Some((ip, p)) => (ip, Some(p)),
        None => (s, None),
    };

    // Try IPv4 first (cheaper and unambiguous — ':' is illegal in IPv4).
    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
        let prefix: u8 = match prefix_str {
            Some(p) => p.parse().ok().filter(|&p: &u8| p <= 32)?,
            None => 32,
        };
        let network = u32::from(ip);
        let mask = if prefix == 0 {
            0
        } else if prefix == 32 {
            u32::MAX
        } else {
            (!0u32) << (32 - prefix)
        };
        return Some(ParsedEntry::V4(CidrV4 {
            network: network & mask,
            mask,
        }));
    }

    // Fall back to IPv6.
    let ip: Ipv6Addr = ip_str.parse().ok()?;
    let prefix: u8 = match prefix_str {
        Some(p) => p.parse().ok().filter(|&p: &u8| p <= 128)?,
        None => 128,
    };
    let octets = ip.octets();
    let mut network = [0u8; 16];
    let full_bytes = (prefix / 8) as usize;
    network[..full_bytes].copy_from_slice(&octets[..full_bytes]);
    if full_bytes < 16 {
        let leftover = prefix % 8;
        if leftover != 0 {
            let mask = (!0u8) << (8 - leftover);
            network[full_bytes] = octets[full_bytes] & mask;
        }
    }
    Some(ParsedEntry::V6(CidrV6 { network, prefix }))
}

/// Compare two 16-byte IPv6 addresses under a `/prefix` mask. The `prefix`
/// high-order bits must match; lower bits are ignored on both sides (callers
/// pre-zero host bits in `network`, but we also mask `addr` for safety).
fn masked_eq(addr: &[u8; 16], network: &[u8; 16], prefix: u8) -> bool {
    let full_bytes = (prefix / 8) as usize;
    if addr[..full_bytes] != network[..full_bytes] {
        return false;
    }
    let leftover = prefix % 8;
    if leftover == 0 {
        return true;
    }
    let mask = (!0u8) << (8 - leftover);
    (addr[full_bytes] & mask) == (network[full_bytes] & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().unwrap())
    }
    fn ip6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse().unwrap())
    }

    // ---------- IPv4 parsing (unchanged behaviour) ----------

    #[test]
    fn parse_single_ipv4() {
        let l = ExcludeList::from_strs(["1.2.3.4"]).unwrap();
        assert_eq!(l.len(), 1);
        assert!(l.contains(ip4("1.2.3.4")));
        assert!(!l.contains(ip4("1.2.3.5")));
    }

    #[test]
    fn parse_ipv4_cidr() {
        let l = ExcludeList::from_strs(["10.0.0.0/8"]).unwrap();
        assert!(l.contains(ip4("10.255.255.255")));
        assert!(l.contains(ip4("10.0.0.1")));
        assert!(!l.contains(ip4("11.0.0.0")));
        assert!(!l.contains(ip4("9.255.255.255")));
    }

    #[test]
    fn parse_multiple_ipv4() {
        let l = ExcludeList::from_strs(["1.1.1.1", "2.2.2.0/24"]).unwrap();
        assert_eq!(l.len(), 2);
        assert!(l.contains(ip4("1.1.1.1")));
        assert!(l.contains(ip4("2.2.2.100")));
        assert!(!l.contains(ip4("1.1.1.2")));
        assert!(!l.contains(ip4("2.2.3.0")));
    }

    #[test]
    fn parse_invalid_ipv4() {
        assert!(ExcludeList::from_strs(["not-an-ip"]).is_err());
        assert!(ExcludeList::from_strs(["1.2.3"]).is_err());
        assert!(ExcludeList::from_strs(["1.2.3.4.5"]).is_err());
        assert!(ExcludeList::from_strs(["256.1.1.1"]).is_err());
    }

    #[test]
    fn parse_invalid_cidr() {
        assert!(ExcludeList::from_strs(["1.2.3.4/33"]).is_err());
        assert!(ExcludeList::from_strs(["1.2.3.4/abc"]).is_err());
        assert!(ExcludeList::from_strs(["1.2.3.4/"]).is_err());
        assert!(ExcludeList::from_strs(["/8"]).is_err());
    }

    #[test]
    fn parse_empty_strings_skipped() {
        let l = ExcludeList::from_strs(["", "  ", "1.2.3.4"]).unwrap();
        assert_eq!(l.len(), 1);
    }

    #[test]
    fn parse_empty_list() {
        let l = ExcludeList::from_strs::<[&str; 0]>([]).unwrap();
        assert!(l.is_empty());
        assert!(!l.contains(ip4("1.1.1.1")));
    }

    #[test]
    fn first_invalid_returns_error() {
        let err = ExcludeList::from_strs(["1.1.1.1", "garbage", "2.2.2.2"]).unwrap_err();
        assert!(err.contains("garbage"));
    }

    #[test]
    fn cidr_boundary_0_matches_all_ipv4() {
        let l = ExcludeList::from_strs(["0.0.0.0/0"]).unwrap();
        assert!(l.contains(ip4("1.2.3.4")));
        assert!(l.contains(ip4("255.255.255.255")));
        assert!(l.contains(ip4("0.0.0.0")));
    }

    #[test]
    fn cidr_boundary_32_matches_exact() {
        let l = ExcludeList::from_strs(["1.2.3.4/32"]).unwrap();
        assert!(l.contains(ip4("1.2.3.4")));
        assert!(!l.contains(ip4("1.2.3.5")));
    }

    #[test]
    fn cidr_normalizes_host_bits() {
        // 10.0.0.5/24 should match 10.0.0.0-10.0.0.255 same as 10.0.0.0/24
        let l = ExcludeList::from_strs(["10.0.0.5/24"]).unwrap();
        assert!(l.contains(ip4("10.0.0.0")));
        assert!(l.contains(ip4("10.0.0.255")));
        assert!(!l.contains(ip4("10.0.1.0")));
    }

    // ---------- IPv6 parsing ----------

    #[test]
    fn parse_single_ipv6() {
        let l = ExcludeList::from_strs(["::1"]).unwrap();
        assert_eq!(l.len(), 1);
        assert!(l.contains(ip6("::1")));
        assert!(!l.contains(ip6("::2")));
    }

    #[test]
    fn parse_ipv6_cidr_128_default() {
        // No prefix → /128 (single host).
        let l = ExcludeList::from_strs(["2001:db8::1"]).unwrap();
        assert!(l.contains(ip6("2001:db8::1")));
        assert!(!l.contains(ip6("2001:db8::2")));
    }

    #[test]
    fn parse_ipv6_cidr_64() {
        let l = ExcludeList::from_strs(["2001:db8::/64"]).unwrap();
        assert!(l.contains(ip6("2001:db8::1")));
        assert!(l.contains(ip6("2001:db8:0:0:ffff:ffff:ffff:ffff")));
        assert!(!l.contains(ip6("2001:db8:0:1::1")));
    }

    #[test]
    fn parse_ipv6_cidr_32() {
        let l = ExcludeList::from_strs(["2001:db8::/32"]).unwrap();
        assert!(l.contains(ip6("2001:db8::1")));
        assert!(l.contains(ip6("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")));
        assert!(!l.contains(ip6("2001:db9::")));
    }

    #[test]
    fn parse_ipv6_cidr_boundary_0_matches_all() {
        let l = ExcludeList::from_strs(["::/0"]).unwrap();
        assert!(l.contains(ip6("::1")));
        assert!(l.contains(ip6("2001:db8::1")));
        assert!(l.contains(ip6("ff00::1")));
    }

    #[test]
    fn parse_ipv6_cidr_boundary_128_matches_exact() {
        let l = ExcludeList::from_strs(["::1/128"]).unwrap();
        assert!(l.contains(ip6("::1")));
        assert!(!l.contains(ip6("::2")));
    }

    #[test]
    fn parse_ipv6_cidr_normalizes_host_bits() {
        // 2001:db8::1/64 should match all of 2001:db8:0:0::/64.
        let l = ExcludeList::from_strs(["2001:db8::1/64"]).unwrap();
        assert!(l.contains(ip6("2001:db8::")));
        assert!(l.contains(ip6("2001:db8:0:0:ffff::")));
        assert!(!l.contains(ip6("2001:db8:0:1::")));
    }

    #[test]
    fn parse_ipv6_cidr_non_byte_boundary() {
        // /36 = 4 full bytes (32 bits) + 4 leftover bits in byte 4.
        // Network bytes 0..3 are fully compared; byte 4 upper nibble must match.
        let l = ExcludeList::from_strs(["2001:db8::/36"]).unwrap();
        // Same first 32 bits as 2001:db8::, byte 4 in 0x00..0x0f → matches.
        assert!(l.contains(ip6("2001:db8::")));
        assert!(l.contains(ip6("2001:db8:0fff::")));
        // Byte 4 upper nibble = 1 (0x10..0x1f) → does NOT match.
        assert!(!l.contains(ip6("2001:db8:1000::")));
        // Different first 32 bits → does NOT match.
        assert!(!l.contains(ip6("2001:db9::")));
        assert!(!l.contains(ip6("2001:dbf::")));
    }

    #[test]
    fn parse_invalid_ipv6() {
        assert!(ExcludeList::from_strs(["::g"]).is_err());
        assert!(ExcludeList::from_strs(["2001:db8::/129"]).is_err());
        assert!(ExcludeList::from_strs(["2001:db8::/abc"]).is_err());
        assert!(ExcludeList::from_strs(["2001:db8::1/32/64"]).is_err());
    }

    // ---------- Mixed lists ----------

    #[test]
    fn mixed_v4_v6_list() {
        let l = ExcludeList::from_strs(["10.0.0.0/8", "::1", "2001:db8::/32"]).unwrap();
        assert_eq!(l.len(), 3);
        assert!(l.contains(ip4("10.1.2.3")));
        assert!(!l.contains(ip4("11.1.2.3")));
        assert!(l.contains(ip6("::1")));
        assert!(l.contains(ip6("2001:db8::abcd")));
        assert!(!l.contains(ip6("::2")));
        assert!(!l.contains(ip6("2001:db9::")));
    }

    #[test]
    fn v4_does_not_match_v6_entries_and_vice_versa() {
        let l = ExcludeList::from_strs(["10.0.0.0/8"]).unwrap();
        // IPv4-mapped IPv6 (::ffff:10.0.0.1) must NOT match an IPv4 entry —
        // we treat the two families as disjoint namespaces. (Callers always
        // see the family of the original-destination sockaddr.)
        assert!(!l.contains(ip6("::ffff:10.0.0.1")));
        assert!(!l.contains(ip6("::1")));

        let l = ExcludeList::from_strs(["::1"]).unwrap();
        assert!(!l.contains(ip4("127.0.0.1")));
        assert!(!l.contains(ip4("0.0.0.1")));
    }
}
