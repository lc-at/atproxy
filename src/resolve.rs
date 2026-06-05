// SPDX-License-Identifier: MIT
use std::net::{SocketAddr, SocketAddrV4};
use std::process::Command;
use tokio::net::lookup_host;
use tracing::{debug, error, info};

/// Why proxy address resolution failed.
#[derive(Debug)]
pub enum ProxyResolveError {
    /// getaddrinfo / DNS lookup failed (NXDOMAIN, network down, etc.).
    Resolve(std::io::Error),
    /// Hostname resolved, but produced no IPv4 addresses (e.g. AAAA-only).
    NoIpv4,
}

impl std::fmt::Display for ProxyResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Resolve(e) => write!(f, "DNS resolution failed: {e}"),
            Self::NoIpv4 => write!(
                f,
                "no IPv4 address resolved (hostnames that resolve to IPv6-only are not supported)"
            ),
        }
    }
}

impl std::error::Error for ProxyResolveError {}

/// Resolve a `host:port` proxy address to an IPv4 socket address.
///
/// `host` may be an IPv4 literal (`1.2.3.4`) or a DNS hostname
/// (`proxy.example.com`). When the hostname resolves to multiple addresses
/// (mixed A/AAAA, or multiple A records), the first IPv4 result is used.
/// IPv6 results are skipped silently — CONNECT only supports IPv4 in
/// `atproxy` today.
///
/// Errors:
/// - [`ProxyResolveError::Resolve`] — DNS lookup failed (NXDOMAIN, network
///   down, etc.).
/// - [`ProxyResolveError::NoIpv4`] — hostname resolved but produced only
///   IPv6 / no IPv4 records.
pub async fn resolve_proxy_addr(
    host: &str,
    port: u16,
) -> Result<SocketAddrV4, ProxyResolveError> {
    let lookup = format!("{host}:{port}");
    let addrs = lookup_host(&lookup)
        .await
        .map_err(ProxyResolveError::Resolve)?;
    pick_ipv4(addrs).ok_or(ProxyResolveError::NoIpv4)
}

/// Pick the first IPv4 address out of an iterator of socket addresses.
///
/// Factored out of [`resolve_proxy_addr`] so it can be unit-tested without
/// going through the system resolver. Returns `None` if the iterator yields
/// no IPv4 entries.
pub fn pick_ipv4<I>(addrs: I) -> Option<SocketAddrV4>
where
    I: IntoIterator<Item = SocketAddr>,
{
    addrs
        .into_iter()
        .find_map(|a| match a {
            SocketAddr::V4(v4) => Some(v4),
            SocketAddr::V6(_) => None,
        })
}

/// Reverse of [`pick_ipv4`] for diagnostics: does the iterator contain any
/// IPv6 entries? Useful for the "no IPv4" error path so we can mention whether
/// the hostname is IPv6-only or simply unresolvable.
#[allow(dead_code)]
pub fn any_ipv6<I>(addrs: I) -> bool
where
    I: IntoIterator<Item = SocketAddr>,
{
    addrs.into_iter().any(|a| matches!(a, SocketAddr::V6(_)))
}

/// Resolve an Android package name to its numeric UID.
///
/// Runs `pm list packages -U` on the device and parses the output, which
/// has lines in the format:
///
/// ```text
/// package:com.example.app uid:10188
/// ```
///
/// Returns `None` if the command fails or the package is not found.
pub fn resolve_uid(package: &str) -> Option<u32> {
    info!(package, "resolving package name to UID");

    let output = match Command::new("pm").args(["list", "packages", "-U"]).output() {
        Ok(o) => o,
        Err(e) => {
            error!(package, error = %e, "failed to execute `pm list packages -U`");
            return None;
        }
    };

    if !output.status.success() {
        error!(
            package,
            exit_code = output.status.code().unwrap_or(-1),
            "`pm list packages -U` exited with error"
        );
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_uid_from_output(package, &stdout)
}

/// Parse a UID from `pm list packages -U` output for a given package name.
fn parse_uid_from_output(package: &str, stdout: &str) -> Option<u32> {
    for line in stdout.lines() {
        // Format: package:com.example.app uid:10188
        // Parse the package field exactly to avoid substring false matches
        // (e.g. "com.example.app" must not match "com.example.app.debug").
        let Some(rest) = line.strip_prefix("package:") else {
            continue;
        };
        let Some(space) = rest.find(' ') else {
            continue;
        };
        let pkg_name = &rest[..space];
        if pkg_name != package {
            continue;
        }
        if let Some(uid_part) = rest[space + 1..].strip_prefix("uid:")
        {
            // Android may return multiple comma-separated UIDs
            // (e.g. "uid:10302,1010302" for real UID + isolated process UID).
            // Take the first one as the primary UID.
            let first_uid = uid_part.trim().split(',').next().unwrap_or(uid_part.trim());
            if let Ok(uid) = first_uid.parse::<u32>() {
                debug!(package, uid, "resolved package to UID");
                return Some(uid);
            }
        }
    }

    error!(package, "package not found in `pm list packages -U` output");
    None
}

/// Resolve a target string into a list of UIDs.
///
/// The target can be:
/// - A package name (contains a `.`) → resolved via `pm list packages -U`
/// - A single numeric UID (e.g. `10188`)
/// - Multiple comma-separated UIDs (e.g. `10188,10200,10300`)
///
/// Returns `None` if any part fails to resolve.
pub fn resolve_target(target: &str) -> Option<Vec<u32>> {
    // If it contains a dot, treat as a package name.
    if target.contains('.') {
        let uid = resolve_uid(target)?;
        Some(vec![uid])
    } else if target.contains(',') {
        // Comma-separated UIDs.
        let mut uids = Vec::new();
        for part in target.split(',') {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                error!("empty UID in comma-separated list");
                return None;
            }
            match trimmed.parse::<u32>() {
                Ok(uid) => uids.push(uid),
                Err(e) => {
                    error!(part = trimmed, error = %e, "invalid UID in comma-separated list");
                    return None;
                }
            }
        }
        if uids.is_empty() {
            error!("no valid UIDs in target");
            return None;
        }
        Some(uids)
    } else {
        // Single numeric UID.
        match target.parse::<u32>() {
            Ok(uid) => Some(vec![uid]),
            Err(e) => {
                error!(target, error = %e, "target is not a valid UID or package name");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_uid_exact_match() {
        let out = "package:com.example.app uid:10188\npackage:com.other.app uid:10200\n";
        assert_eq!(parse_uid_from_output("com.example.app", out), Some(10188));
        assert_eq!(parse_uid_from_output("com.other.app", out), Some(10200));
    }

    #[test]
    fn test_parse_uid_no_substring_false_positive() {
        let out = "package:com.example.app uid:10188\npackage:com.example.app.debug uid:10200\n";
        assert_eq!(parse_uid_from_output("com.example.app", out), Some(10188));
        assert_eq!(
            parse_uid_from_output("com.example.app.debug", out),
            Some(10200)
        );
    }

    #[test]
    fn test_parse_uid_not_found() {
        let out = "package:com.example.app uid:10188\n";
        assert_eq!(parse_uid_from_output("com.nonexistent", out), None);
    }

    #[test]
    fn test_parse_uid_multi_uid_field() {
        // Android can return "uid:10302,1010302" (real UID + isolated process UID).
        let out = "package:com.grabtaxi.passenger uid:10302,1010302\n";
        assert_eq!(
            parse_uid_from_output("com.grabtaxi.passenger", out),
            Some(10302)
        );
    }

    #[test]
    fn test_parse_uid_partial_name_no_match() {
        let out = "package:com.example.app uid:10188\npackage:com.other.app uid:10200\n";
        assert_eq!(parse_uid_from_output("com.app", out), None);
        assert_eq!(parse_uid_from_output("com.other", out), None);
    }

    #[test]
    fn test_resolve_target_single_uid() {
        assert_eq!(resolve_target("10188"), Some(vec![10188]));
    }

    #[test]
    fn test_resolve_target_comma_uids() {
        assert_eq!(
            resolve_target("10188,10200,10300"),
            Some(vec![10188, 10200, 10300])
        );
    }

    #[test]
    fn test_resolve_target_comma_uids_with_spaces() {
        assert_eq!(
            resolve_target("10188, 10200 , 10300"),
            Some(vec![10188, 10200, 10300])
        );
    }

    #[test]
    fn test_resolve_target_bad_uid() {
        assert_eq!(resolve_target("abc"), None);
    }

    #[test]
    fn test_resolve_target_bad_comma_mixed() {
        assert_eq!(resolve_target("10188,abc,10300"), None);
    }

    #[test]
    fn test_resolve_target_empty_comma_part() {
        assert_eq!(resolve_target("10188,,10300"), None);
    }

    // Package name resolution requires `pm` binary (Android), tested via
    // parse_uid_from_output above. resolve_target with dots calls resolve_uid
    // which invokes `pm` (not testable outside Android).

    // ---------- pick_ipv4 (deterministic, no DNS) ----------

    fn v4(a: u8, b: u8, c: u8, d: u8, p: u16) -> SocketAddr {
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d)), p)
    }
    fn v6(p: u16) -> SocketAddr {
        SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), p)
    }

    #[test]
    fn test_pick_ipv4_only_ipv4() {
        let addrs = vec![v4(10, 0, 0, 1, 8080)];
        let got = pick_ipv4(addrs).unwrap();
        assert_eq!(got.ip(), &std::net::Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(got.port(), 8080);
    }

    #[test]
    fn test_pick_ipv4_skips_v6_then_picks_v4() {
        // Regression: when getaddrinfo returns AAAA first (RFC 3484 policy on
        // some hosts), the picker must continue scanning, not return None.
        let addrs = vec![v6(8080), v6(8080), v4(10, 0, 0, 1, 8080)];
        let got = pick_ipv4(addrs).unwrap();
        assert_eq!(got.ip(), &std::net::Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn test_pick_ipv4_picks_first_v4_when_multiple() {
        let addrs = vec![v4(10, 0, 0, 1, 8080), v4(192, 168, 0, 1, 8080)];
        let got = pick_ipv4(addrs).unwrap();
        assert_eq!(got.ip(), &std::net::Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn test_pick_ipv4_only_v6_returns_none() {
        // Regression: AAAA-only hostname must surface as NoIpv4, not panic.
        let addrs = vec![v6(8080), v6(8080)];
        assert!(pick_ipv4(addrs).is_none());
    }

    #[test]
    fn test_pick_ipv4_empty() {
        assert!(pick_ipv4(std::iter::empty()).is_none());
    }

    #[test]
    fn test_any_ipv6_detects_v6() {
        assert!(any_ipv6(vec![v4(1, 2, 3, 4, 80), v6(80)]));
        assert!(!any_ipv6(vec![v4(1, 2, 3, 4, 80)]));
        assert!(!any_ipv6(vec![]));
    }

    // ---------- resolve_proxy_addr (uses real DNS) ----------
    //
    // These tests touch the system resolver, so they rely on a working
    // network/DNS environment. localhost always resolves on the dev/test host
    // and a `.invalid` TLD is reserved by RFC 2606 to never resolve.

    #[tokio::test]
    async fn test_resolve_proxy_addr_ipv4_literal() {
        // An IP literal goes through lookup_host but should come straight back.
        let addr = resolve_proxy_addr("127.0.0.1", 8080).await.unwrap();
        assert_eq!(addr.ip(), &std::net::Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(addr.port(), 8080);
    }

    #[tokio::test]
    async fn test_resolve_proxy_addr_localhost() {
        // localhost reliably resolves on Linux dev hosts (via /etc/hosts).
        // We don't assert the IP because some setups map it to ::1 only,
        // but `localhost` is guaranteed to have *at least* an A record on a
        // normal Linux box. If the host has no IPv4 mapping for localhost,
        // the test environment is unusual and the failure is informative.
        let result = resolve_proxy_addr("localhost", 8080).await;
        assert!(result.is_ok(), "localhost must resolve: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_resolve_proxy_addr_nxdomain() {
        // .invalid is reserved by RFC 2606 and must never resolve.
        let result = resolve_proxy_addr("atproxy-test-definitely-nonexistent.invalid", 80)
            .await;
        assert!(
            matches!(result, Err(ProxyResolveError::Resolve(_))),
            "expected Resolve error for .invalid, got {:?}",
            result
        );
    }
}
