// SPDX-License-Identifier: MIT
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::process::Command;
use tokio::net::lookup_host;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

/// Why proxy address resolution failed.
#[derive(Debug)]
pub enum ProxyResolveError {
    /// Both the system resolver and the direct UDP DNS fallback failed
    /// (NXDOMAIN, network down, all DNS servers unreachable, etc.).
    Resolve(std::io::Error),
}

impl std::fmt::Display for ProxyResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Resolve(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ProxyResolveError {}

/// Resolve a `host:port` proxy address to an IPv4 socket address.
///
/// `host` may be an IPv4 literal (`1.2.3.4`) or a DNS hostname
/// (`proxy.example.com`). Resolution is done in two stages:
///
/// 1. Try the system resolver via `tokio::net::lookup_host`. On glibc Linux
///    this reads `/etc/resolv.conf` and works normally.
/// 2. If that fails or returns no IPv4 results, fall back to a tiny built-in
///    UDP DNS client that talks to `dns_servers` directly (default
///    `1.1.1.1`, `8.8.8.8`). This is necessary on Android, where musl's
///    `getaddrinfo` cannot reach the system's NetD daemon and `/etc/resolv.conf`
///    typically doesn't exist — without this fallback, only entries in
///    `/etc/hosts` (i.e. `localhost`) resolve.
///
/// IPv6 results from either resolver are skipped silently — CONNECT only
/// supports IPv4 in `atproxy` today.
///
/// Errors:
/// - [`ProxyResolveError::Resolve`] — both resolver stages failed.
pub async fn resolve_proxy_addr(
    host: &str,
    port: u16,
    dns_servers: &[Ipv4Addr],
) -> Result<SocketAddrV4, ProxyResolveError> {
    // Fast path: literal IPv4 (no DNS at all).
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(SocketAddrV4::new(ip, port));
    }

    let lookup = format!("{host}:{port}");

    // Stage 1: system resolver.
    let sys_result = match lookup_host(&lookup).await {
        Ok(addrs) => pick_ipv4(addrs),
        Err(e) => {
            debug!(host, error = %e, "system resolver failed; falling back to direct UDP DNS");
            None
        }
    };
    if let Some(addr) = sys_result {
        debug!(host, %addr, "resolved via system resolver");
        return Ok(SocketAddrV4::new(*addr.ip(), port));
    }

    // Stage 2: direct UDP DNS against the configured/sensible defaults.
    debug!(host, servers = ?dns_servers, "resolving via direct UDP DNS");
    let ip = dns_lookup_a(host, dns_servers)
        .await
        .map_err(ProxyResolveError::Resolve)?;
    Ok(SocketAddrV4::new(ip, port))
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

// =====================================================================
// Direct UDP DNS client (fallback for environments where getaddrinfo is
// broken — most notably musl on Android, which has no /etc/resolv.conf and
// no path to the NetD daemon).
// =====================================================================

const DNS_PORT: u16 = 53;
const DNS_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
/// Max DNS UDP payload we'll accept (RFC 1035 limits UDP to 512 bytes; EDNS
/// extends this but we keep it simple).
const DNS_BUFSIZE: usize = 512;

/// Resolve an A record for `name` by sending UDP DNS queries to each server
/// in `servers`, returning the first IPv4 answer found.
///
/// Iterates through servers in order; the first one that returns a usable
/// answer wins. Each query has a 3-second timeout. Returns `Err` if every
/// server fails or all answers are non-A.
///
/// `ErrorKind::NotFound` (NXDOMAIN or "no A record in response") is treated
/// as authoritative and short-circuits — the other servers are not tried
/// because the name genuinely doesn't exist. Other errors (timeout, network,
/// malformed response) cause iteration to continue with the next server.
pub async fn dns_lookup_a(name: &str, servers: &[Ipv4Addr]) -> std::io::Result<Ipv4Addr> {
    if servers.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no DNS servers configured",
        ));
    }

    // Build the query once and reuse it for each server.
    let query = build_dns_a_query(name)?;

    let mut last_err: Option<std::io::Error> = None;
    for &server in servers {
        match query_server_once(server, &query).await {
            Ok(ip) => {
                debug!(name, server = %server, ip = %ip, "DNS A record resolved");
                return Ok(ip);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // NXDOMAIN / empty answer — the name doesn't exist; don't
                // waste round-trips on the other servers.
                return Err(e);
            }
            Err(e) => {
                warn!(server = %server, error = %e, "DNS query failed; trying next server");
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "all DNS servers failed".to_string(),
        )
    }))
}

async fn query_server_once(server: Ipv4Addr, query: &[u8]) -> std::io::Result<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect(SocketAddrV4::new(server, DNS_PORT)).await?;
    sock.send(query).await?;

    let mut buf = vec![0u8; DNS_BUFSIZE];
    let n = tokio::time::timeout(DNS_QUERY_TIMEOUT, sock.recv(&mut buf)).await??;
    buf.truncate(n);

    parse_dns_a_response(&buf, query)
}

/// Build a minimal DNS A-record query message for `name`.
///
/// Header: 12 bytes (id=0x1234, flags=0x0100 recursion-desired, qdcount=1).
/// Question: <qname> <qtype=A=1> <qclass=IN=1>.
fn build_dns_a_query(name: &str) -> std::io::Result<Vec<u8>> {
    // Sanity: hostnames must be <=253 octets and each label <=63.
    if name.is_empty() || name.len() > 253 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid hostname length",
        ));
    }

    let mut buf = Vec::with_capacity(64);
    // Header.
    buf.extend_from_slice(&[
        0x12, 0x34, // id (arbitrary; we use it to validate the response)
        0x01, 0x00, // flags: standard query, recursion desired
        0x00, 0x01, // qdcount: 1
        0x00, 0x00, // ancount: 0
        0x00, 0x00, // nscount: 0
        0x00, 0x00, // arcount: 0
    ]);
    // QNAME: <len><label>...<0>
    for label in name.split('.') {
        if label.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "empty label in hostname",
            ));
        }
        if label.len() > 63 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "label too long (>63)",
            ));
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // terminator
    // QTYPE = A (1)
    buf.extend_from_slice(&[0x00, 0x01]);
    // QCLASS = IN (1)
    buf.extend_from_slice(&[0x00, 0x01]);
    Ok(buf)
}

/// Parse a DNS response and return the first A record answer.
///
/// Verifies:
/// - The response ID matches the query ID (best-effort defense against spoofing).
/// - The response flag (QR) is set.
/// - The RCODE in the header is 0 (NOERROR) — returns `NotFound` otherwise.
/// - At least one answer with TYPE=A and CLASS=IN exists with a 4-byte RDLENGTH.
fn parse_dns_a_response(resp: &[u8], query: &[u8]) -> std::io::Result<Ipv4Addr> {
    if resp.len() < 12 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "DNS response too short (<12 bytes)",
        ));
    }

    // Validate ID matches the query.
    if resp[..2] != query[..2] {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "DNS response ID does not match query",
        ));
    }

    // QR flag must be 1 (response).
    if resp[2] & 0x80 == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "DNS message is not a response (QR bit not set)",
        ));
    }

    // RCODE is the low 4 bits of byte 3.
    let rcode = resp[3] & 0x0F;
    if rcode != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("DNS server returned RCODE {rcode}"),
        ));
    }

    let qdcount = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;

    let mut pos = 12;

    // Skip question section.
    for _ in 0..qdcount {
        pos = skip_qname(resp, pos)?;
        pos = pos
            .checked_add(4)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "EOF in question"))?;
    }
    if pos > resp.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "DNS response truncated during question section",
        ));
    }

    // Walk answer section looking for the first A record.
    for _ in 0..ancount {
        pos = skip_qname(resp, pos)?;
        if pos + 10 > resp.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "DNS answer truncated",
            ));
        }
        let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let _rclass = u16::from_be_bytes([resp[pos + 2], resp[pos + 3]]);
        let rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > resp.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "DNS answer RDATA overruns buffer",
            ));
        }
        if rtype == 1 && rdlength == 4 {
            let ip = Ipv4Addr::new(
                resp[pos],
                resp[pos + 1],
                resp[pos + 2],
                resp[pos + 3],
            );
            return Ok(ip);
        }
        pos += rdlength;
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "DNS response had no A records",
    ))
}

/// Skip a (possibly-compressed) DNS name starting at `pos`. Returns the
/// position immediately after the name (after the terminating null byte, or
/// after the pointer for compressed names).
fn skip_qname(buf: &[u8], mut pos: usize) -> std::io::Result<usize> {
    loop {
        if pos >= buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "DNS name overrun",
            ));
        }
        let len = buf[pos];
        if len == 0 {
            return Ok(pos + 1);
        }
        // Compression pointer: top two bits = 11.
        if (len & 0xC0) == 0xC0 {
            return Ok(pos + 2);
        }
        // Regular label.
        pos += 1 + len as usize;
    }
}

/// Parse `/etc/resolv.conf`-style file and extract `nameserver` entries.
/// Returns an empty vec if the file doesn't exist or has no nameservers.
pub fn parse_resolv_conf(path: &str) -> Vec<Ipv4Addr> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut servers = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some(rest) = line.strip_prefix("nameserver") else {
            continue;
        };
        let ip_str = rest.trim();
        if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
            servers.push(ip);
        }
    }
    servers
}

/// Default fallback DNS servers used when `/etc/resolv.conf` is missing or
/// empty (i.e. on Android, where the file doesn't exist). Cloudflare and
/// Google public resolvers — broadly reachable, support DNSSEC, no hijacking.
pub const DEFAULT_DNS_SERVERS: [Ipv4Addr; 4] = [
    Ipv4Addr::new(1, 1, 1, 1), // Cloudflare
    Ipv4Addr::new(8, 8, 8, 8), // Google
    Ipv4Addr::new(1, 0, 0, 1), // Cloudflare secondary
    Ipv4Addr::new(8, 8, 4, 4), // Google secondary
];

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
        let addr = resolve_proxy_addr("127.0.0.1", 8080, &DEFAULT_DNS_SERVERS)
            .await
            .unwrap();
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
        let result = resolve_proxy_addr("localhost", 8080, &DEFAULT_DNS_SERVERS).await;
        assert!(result.is_ok(), "localhost must resolve: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_resolve_proxy_addr_nxdomain() {
        // .invalid is reserved by RFC 2606 and must never resolve.
        // Both stages (system resolver + direct UDP) should reject it.
        let result = resolve_proxy_addr(
            "atproxy-test-definitely-nonexistent.invalid",
            80,
            &DEFAULT_DNS_SERVERS,
        )
        .await;
        assert!(
            matches!(result, Err(ProxyResolveError::Resolve(_))),
            "expected Resolve error for .invalid, got {:?}",
            result
        );
    }

    // ---------- build_dns_a_query ----------

    #[test]
    fn test_build_dns_a_query_simple() {
        let q = build_dns_a_query("example.com").unwrap();
        // Header.
        assert_eq!(&q[0..2], &[0x12, 0x34]); // id
        assert_eq!(&q[2..4], &[0x01, 0x00]); // flags: RD
        assert_eq!(&q[4..6], &[0x00, 0x01]); // qdcount
        assert_eq!(&q[6..8], &[0x00, 0x00]); // ancount
        assert_eq!(&q[8..10], &[0x00, 0x00]); // nscount
        assert_eq!(&q[10..12], &[0x00, 0x00]); // arcount
        // QNAME: 7 example 3 com 0
        assert_eq!(&q[12..13], &[7]);
        assert_eq!(&q[13..20], b"example");
        assert_eq!(&q[20..21], &[3]);
        assert_eq!(&q[21..24], b"com");
        assert_eq!(&q[24..25], &[0]); // terminator
                                      // QTYPE = A, QCLASS = IN.
        assert_eq!(&q[25..27], &[0x00, 0x01]);
        assert_eq!(&q[27..29], &[0x00, 0x01]);
        assert_eq!(q.len(), 29);
    }

    #[test]
    fn test_build_dns_a_query_subdomain() {
        let q = build_dns_a_query("a.b.example.org").unwrap();
        // Just sanity-check the label-length byte sequence.
        let labels: Vec<u8> = q[12..]
            .iter()
            .take_while(|&&b| b != 0)
            .copied()
            .collect();
        assert_eq!(labels, vec![1, b'a', 1, b'b', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'o', b'r', b'g']);
    }

    #[test]
    fn test_build_dns_a_query_rejects_empty() {
        assert!(build_dns_a_query("").is_err());
    }

    #[test]
    fn test_build_dns_a_query_rejects_too_long() {
        let long = "a".repeat(254);
        assert!(build_dns_a_query(&long).is_err());
    }

    #[test]
    fn test_build_dns_a_query_rejects_empty_label() {
        assert!(build_dns_a_query("example..com").is_err());
        assert!(build_dns_a_query(".example.com").is_err());
        assert!(build_dns_a_query("example.com.").is_err());
    }

    #[test]
    fn test_build_dns_a_query_rejects_long_label() {
        let label = "a".repeat(64);
        assert!(build_dns_a_query(&format!("{label}.com")).is_err());
    }

    // ---------- skip_qname ----------

    #[test]
    fn test_skip_qname_simple() {
        // 3 com 0
        let buf = [3, b'c', b'o', b'm', 0];
        let next = skip_qname(&buf, 0).unwrap();
        assert_eq!(next, 5);
    }

    #[test]
    fn test_skip_qname_compressed_pointer() {
        // 0xC0 0x0C = pointer to offset 12 (compression).
        let buf = [0xC0, 0x0C];
        let next = skip_qname(&buf, 0).unwrap();
        assert_eq!(next, 2);
    }

    #[test]
    fn test_skip_qname_overrun() {
        // Label length byte claims bytes beyond buffer end.
        let buf = [10, b'a'];
        assert!(skip_qname(&buf, 0).is_err());
    }

    #[test]
    fn test_skip_qname_empty_buffer() {
        let buf: [u8; 0] = [];
        let result = skip_qname(&buf, 0);
        assert!(result.is_err());
    }

    // ---------- parse_dns_a_response ----------

    fn make_query_for(name: &str) -> Vec<u8> {
        build_dns_a_query(name).unwrap()
    }

    #[test]
    fn test_parse_dns_a_response_ok() {
        // Synthesize a minimal valid response for "example.com" → 93.184.215.14
        let query = make_query_for("example.com");
        let mut resp = query.clone();
        // Set QR=1, RA=1, RCODE=0 in flags (bytes 2..3).
        resp[2] |= 0x80; // QR
        resp[3] |= 0x80; // RA
        // ancount = 1
        resp[6] = 0;
        resp[7] = 1;
        // Append answer: pointer to existing qname (0xC0 0x0C), TYPE=A, CLASS=IN,
        // TTL=300, RDLENGTH=4, RDATA=93.184.215.14.
        resp.extend_from_slice(&[
            0xC0, 0x0C, // compressed qname
            0x00, 0x01, // TYPE=A
            0x00, 0x01, // CLASS=IN
            0x00, 0x00, 0x01, 0x2C, // TTL=300
            0x00, 0x04, // RDLENGTH=4
            93, 184, 215, 14, // RDATA
        ]);
        let ip = parse_dns_a_response(&resp, &query).unwrap();
        assert_eq!(ip, std::net::Ipv4Addr::new(93, 184, 215, 14));
    }

    #[test]
    fn test_parse_dns_a_response_nxdomain() {
        let query = make_query_for("nope.invalid");
        let mut resp = query.clone();
        resp[2] |= 0x80; // QR
        // RCODE = NXDOMAIN = 3
        resp[3] |= 0x03;
        // ancount stays 0.
        let err = parse_dns_a_response(&resp, &query).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn test_parse_dns_a_response_id_mismatch() {
        let query = make_query_for("example.com");
        let mut resp = query.clone();
        resp[0] ^= 0xFF; // corrupt ID
        resp[2] |= 0x80;
        let err = parse_dns_a_response(&resp, &query).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_parse_dns_a_response_not_a_response() {
        // QR bit not set.
        let query = make_query_for("example.com");
        let resp = query.clone();
        let err = parse_dns_a_response(&resp, &query).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_parse_dns_a_response_skips_cname_picks_a() {
        // Response has CNAME then A record.
        let query = make_query_for("www.example.com");
        let mut resp = query.clone();
        resp[2] |= 0x80;
        resp[6] = 0;
        resp[7] = 2; // ancount=2

        // First answer: CNAME → example.com.
        resp.extend_from_slice(&[
            0xC0, 0x0C, // compressed qname
            0x00, 0x05, // TYPE=CNAME
            0x00, 0x01, // CLASS=IN
            0x00, 0x00, 0x01, 0x2C, // TTL=300
            0x00, 0x0D, // RDLENGTH=13 (11 bytes for "example.com" + 0xC0 0x0C)
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            3, b'c', b'o', b'm', 0,
        ]);
        // Second answer: A → 93.184.215.14.
        resp.extend_from_slice(&[
            0xC0, 0x0C,
            0x00, 0x01, // TYPE=A
            0x00, 0x01, // CLASS=IN
            0x00, 0x00, 0x01, 0x2C, // TTL=300
            0x00, 0x04, // RDLENGTH=4
            93, 184, 215, 14,
        ]);
        let ip = parse_dns_a_response(&resp, &query).unwrap();
        assert_eq!(ip, std::net::Ipv4Addr::new(93, 184, 215, 14));
    }

    #[test]
    fn test_parse_dns_a_response_no_a_records() {
        // Response with NOERROR + 0 answers.
        let query = make_query_for("example.com");
        let mut resp = query.clone();
        resp[2] |= 0x80;
        let err = parse_dns_a_response(&resp, &query).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    // ---------- parse_resolv_conf ----------

    #[test]
    fn test_parse_resolv_conf_basic() {
        let path = "/tmp/atproxy_test_resolv.conf";
        std::fs::write(
            path,
            "# comment\nnameserver 1.1.1.1\nnameserver 8.8.8.8\noptions ndots:1\n",
        )
        .unwrap();
        let servers = parse_resolv_conf(path);
        assert_eq!(
            servers,
            vec![
                std::net::Ipv4Addr::new(1, 1, 1, 1),
                std::net::Ipv4Addr::new(8, 8, 8, 8),
            ]
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_parse_resolv_conf_inline_comment() {
        let path = "/tmp/atproxy_test_resolv.conf";
        std::fs::write(path, "nameserver 1.2.3.4   # primary\n").unwrap();
        let servers = parse_resolv_conf(path);
        assert_eq!(servers, vec![std::net::Ipv4Addr::new(1, 2, 3, 4)]);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_parse_resolv_conf_missing_file() {
        let servers = parse_resolv_conf("/tmp/atproxy-definitely-nonexistent-xyz.conf");
        assert!(servers.is_empty());
    }

    #[test]
    fn test_parse_resolv_conf_ignores_ipv6() {
        let path = "/tmp/atproxy_test_resolv.conf";
        std::fs::write(path, "nameserver 2606:4700:4700::1111\nnameserver 1.1.1.1\n").unwrap();
        let servers = parse_resolv_conf(path);
        // IPv6 entry is silently skipped (parse::<Ipv4Addr> fails).
        assert_eq!(servers, vec![std::net::Ipv4Addr::new(1, 1, 1, 1)]);
        let _ = std::fs::remove_file(path);
    }

    // ---------- dns_lookup_a (real UDP, requires network) ----------
    //
    // These tests send real DNS queries over UDP. They will fail in
    // network-isolated environments; that's expected and informative.

    #[tokio::test]
    async fn test_dns_lookup_a_real_known_hostname() {
        // google.com has had A records continuously for decades.
        let ip = dns_lookup_a("google.com", &[std::net::Ipv4Addr::new(1, 1, 1, 1)])
            .await
            .expect("DNS lookup of google.com via 1.1.1.1 must succeed");
        // Sanity: must be a public, globally routable IPv4 (not 0.0.0.0, not
        // 127.0.0.0/8, not 0.0.0.0/8 — none of which google.com serves).
        assert!(!ip.is_unspecified(), "got {ip}");
        assert!(!ip.is_loopback(), "got {ip}");
        assert!(!ip.is_private(), "got {ip}");
    }

    #[tokio::test]
    async fn test_dns_lookup_a_nxdomain() {
        // .invalid is reserved by RFC 2606 and must never resolve.
        let result = dns_lookup_a(
            "atproxy-test-definitely-nonexistent.invalid",
            &[std::net::Ipv4Addr::new(1, 1, 1, 1)],
        )
        .await;
        assert!(result.is_err(), "expected NXDOMAIN, got {:?}", result.ok());
        if let Err(e) = result {
            assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
        }
    }

    #[tokio::test]
    async fn test_dns_lookup_a_no_servers() {
        let result = dns_lookup_a("google.com", &[]).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn test_dns_lookup_a_falls_through_to_next_server() {
        // First server is unreachable (RFC 5737 TEST-NET-1 — either drops
        // packets or fails fast with ICMP unreachable, depending on routing).
        // Either way, the lookup must succeed via the second (real) server.
        let ip = dns_lookup_a(
            "cloudflare.com",
            &[
                std::net::Ipv4Addr::new(192, 0, 2, 1), // RFC 5737 TEST-NET-1
                std::net::Ipv4Addr::new(1, 1, 1, 1),   // real
            ],
        )
        .await
        .expect("must succeed via 1.1.1.1 after first server fails");
        assert!(!ip.is_unspecified());
        assert!(!ip.is_loopback());
        assert!(!ip.is_private());
    }
}
