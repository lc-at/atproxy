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
//! Entries may be plain IPv4 addresses (treated as `/32`) or CIDR ranges
//! (`a.b.c.d/prefix`). Network bits are normalized so `10.0.0.5/24` and
//! `10.0.0.0/24` behave identically.

use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy)]
struct Entry {
    /// Network address with host bits already zeroed by `mask`.
    network: u32,
    /// Bitmask in host byte order: `prefix` leading 1-bits, rest 0.
    mask: u32,
}

/// A list of IPv4 addresses / CIDR ranges to exclude from upstream proxying.
#[derive(Debug, Clone, Default)]
pub struct ExcludeList {
    entries: Vec<Entry>,
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
        let mut entries = Vec::new();
        for raw in iter {
            let s = raw.trim();
            if s.is_empty() {
                continue;
            }
            let entry = parse_entry(s)
                .ok_or_else(|| format!("invalid IPv4 address or CIDR: '{s}'"))?;
            entries.push(entry);
        }
        Ok(Self { entries })
    }

    /// Returns `true` if the IP matches any entry in the list.
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let ip_u32 = u32::from(ip);
        self.entries.iter().any(|e| (ip_u32 & e.mask) == e.network)
    }

    /// Returns `true` if the list has no entries (no exclusion applies).
    #[allow(dead_code)] // used in tests
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of entries in the list.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Parse one entry: either `a.b.c.d` (treated as `/32`) or `a.b.c.d/prefix`.
fn parse_entry(s: &str) -> Option<Entry> {
    let (ip_str, prefix): (&str, u8) = match s.split_once('/') {
        Some((ip, mask)) => {
            let p: u8 = mask.parse().ok()?;
            if p > 32 {
                return None;
            }
            (ip, p)
        }
        None => (s, 32),
    };
    let ip: Ipv4Addr = ip_str.parse().ok()?;
    let network = u32::from(ip);
    let mask = if prefix == 0 {
        0
    } else if prefix == 32 {
        u32::MAX
    } else {
        (!0u32) << (32 - prefix)
    };
    // Normalize: zero out host bits so `10.0.0.5/24` == `10.0.0.0/24`.
    Some(Entry {
        network: network & mask,
        mask,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    // ---------- parsing ----------

    #[test]
    fn parse_single_ip() {
        let l = ExcludeList::from_strs(["1.2.3.4"]).unwrap();
        assert_eq!(l.len(), 1);
        assert!(l.contains(ip("1.2.3.4")));
        assert!(!l.contains(ip("1.2.3.5")));
    }

    #[test]
    fn parse_cidr() {
        let l = ExcludeList::from_strs(["10.0.0.0/8"]).unwrap();
        assert!(l.contains(ip("10.255.255.255")));
        assert!(l.contains(ip("10.0.0.1")));
        assert!(!l.contains(ip("11.0.0.0")));
        assert!(!l.contains(ip("9.255.255.255")));
    }

    #[test]
    fn parse_multiple() {
        let l = ExcludeList::from_strs(["1.1.1.1", "2.2.2.0/24"]).unwrap();
        assert_eq!(l.len(), 2);
        assert!(l.contains(ip("1.1.1.1")));
        assert!(l.contains(ip("2.2.2.100")));
        assert!(!l.contains(ip("1.1.1.2")));
        assert!(!l.contains(ip("2.2.3.0")));
    }

    #[test]
    fn parse_invalid_ip() {
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
        assert!(!l.contains(ip("1.1.1.1")));
    }

    #[test]
    fn first_invalid_returns_error() {
        let err = ExcludeList::from_strs(["1.1.1.1", "garbage", "2.2.2.2"]).unwrap_err();
        assert!(err.contains("garbage"));
    }

    // ---------- CIDR boundaries ----------

    #[test]
    fn cidr_boundary_0_matches_all() {
        let l = ExcludeList::from_strs(["0.0.0.0/0"]).unwrap();
        assert!(l.contains(ip("1.2.3.4")));
        assert!(l.contains(ip("255.255.255.255")));
        assert!(l.contains(ip("0.0.0.0")));
    }

    #[test]
    fn cidr_boundary_32_matches_exact() {
        let l = ExcludeList::from_strs(["1.2.3.4/32"]).unwrap();
        assert!(l.contains(ip("1.2.3.4")));
        assert!(!l.contains(ip("1.2.3.5")));
    }

    #[test]
    fn cidr_boundary_24() {
        let l = ExcludeList::from_strs(["192.168.1.0/24"]).unwrap();
        assert!(l.contains(ip("192.168.1.0")));
        assert!(l.contains(ip("192.168.1.255")));
        assert!(!l.contains(ip("192.168.2.0")));
        assert!(!l.contains(ip("192.168.0.255")));
    }

    #[test]
    fn cidr_normalizes_host_bits() {
        // 10.0.0.5/24 should match 10.0.0.0-10.0.0.255 same as 10.0.0.0/24
        let l = ExcludeList::from_strs(["10.0.0.5/24"]).unwrap();
        assert!(l.contains(ip("10.0.0.0")));
        assert!(l.contains(ip("10.0.0.255")));
        assert!(!l.contains(ip("10.0.1.0")));
    }

    #[test]
    fn cidr_16_normalizes() {
        let l = ExcludeList::from_strs(["192.168.99.42/16"]).unwrap();
        assert!(l.contains(ip("192.168.0.0")));
        assert!(l.contains(ip("192.168.255.255")));
        assert!(!l.contains(ip("192.169.0.0")));
    }

    #[test]
    fn cidr_31_split() {
        let l = ExcludeList::from_strs(["10.0.0.0/31"]).unwrap();
        assert!(l.contains(ip("10.0.0.0")));
        assert!(l.contains(ip("10.0.0.1")));
        assert!(!l.contains(ip("10.0.0.2")));
        assert!(!l.contains(ip("9.255.255.255")));
    }
}
