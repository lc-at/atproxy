// SPDX-License-Identifier: MIT
//! TCP relay logic: transparent proxy via HTTP CONNECT handshake.
//!
//! Recovers the original destination via `SO_ORIGINAL_DST`. If the destination
//! IP is in the [`ExcludeList`], the connection is relayed directly to the
//! origin (passthrough). Otherwise the connection is tunneled through the
//! upstream proxy via an HTTP CONNECT handshake.

use std::net::SocketAddrV4;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use nix::sys::socket::{getsockopt, sockopt::OriginalDst};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::exclude::ExcludeList;
use crate::stats::Stats;

/// Recover the original destination address from a redirected socket.
pub fn get_original_dst(sock: &TcpStream) -> Option<SocketAddrV4> {
    use std::net::Ipv4Addr;
    let addr = getsockopt(sock, OriginalDst).ok()?;
    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    Some(SocketAddrV4::new(ip, port))
}

/// Set a single integer socket option via libc `setsockopt`.
///
/// # Safety
/// Caller must ensure `fd` is a valid socket file descriptor.
unsafe fn set_sockopt_int(
    fd: libc::c_int,
    level: libc::c_int,
    optname: libc::c_int,
    val: libc::c_int,
) {
    unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            (&raw const val).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

/// Set TCP keepalive parameters on a socket.
pub fn set_keepalive(sock: &TcpStream) {
    let fd = sock.as_raw_fd();
    unsafe {
        set_sockopt_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1);
        set_sockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, 30);
        set_sockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, 10);
        set_sockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT, 3);
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Parse the HTTP status code from the first line of a response header.
///
/// Accepts both `HTTP/1.x 200 Reason` and the (technically RFC-non-compliant
/// but encountered in the wild) `HTTP/1.x 200` form without a reason phrase.
/// Returns `None` on malformed input.
fn parse_status_code(header: &str) -> Option<u16> {
    let first_line = header.split("\r\n").next()?;
    let mut parts = first_line.split_whitespace();
    parts.next()?; // HTTP/1.x
    parts.next()?.parse().ok()
}

/// Perform the HTTP CONNECT handshake with the upstream proxy.
async fn connect_handshake(proxy: &mut TcpStream, target: SocketAddrV4) -> io::Result<Vec<u8>> {
    let req = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
        target.ip(),
        target.port(),
        target.ip(),
        target.port(),
    );
    proxy.write_all(req.as_bytes()).await?;

    let mut buf = vec![0u8; 4096];
    let mut total = 0;

    loop {
        if total >= buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "CONNECT response too large",
            ));
        }
        let n = proxy.read(&mut buf[total..]).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "proxy EOF during CONNECT",
            ));
        }
        total += n;

        if let Some(hdr_end) = find_header_end(&buf[..total]) {
            let header = std::str::from_utf8(&buf[..hdr_end])
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF8 response"))?;

            let code = parse_status_code(header).unwrap_or(0);
            if code != 200 {
                warn!(
                    target_ip = %target.ip(),
                    target_port = target.port(),
                    status_code = code,
                    response = header.lines().next().unwrap_or(""),
                    "proxy rejected CONNECT"
                );
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "proxy rejected CONNECT",
                ));
            }

            return Ok(buf[hdr_end..total].to_vec());
        }
    }
}

/// Handle a single client connection: recover original destination, then
/// either relay directly (if excluded) or establish a CONNECT tunnel.
pub async fn handle(
    client: TcpStream,
    proxy_addr: SocketAddrV4,
    stats: Arc<Stats>,
    excludes: Arc<ExcludeList>,
) {
    stats.conn_open();
    let ok = relay_inner(client, proxy_addr, &stats, &excludes).await.is_ok();
    stats.conn_close(ok);
}

async fn relay_inner(
    client: TcpStream,
    proxy_addr: SocketAddrV4,
    stats: &Stats,
    excludes: &ExcludeList,
) -> io::Result<()> {
    let orig_dst = get_original_dst(&client)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "SO_ORIGINAL_DST failed"))?;

    if excludes.contains(*orig_dst.ip()) {
        debug!(
            ip = %orig_dst.ip(),
            port = orig_dst.port(),
            "destination excluded; direct passthrough"
        );
        return relay_direct(client, orig_dst, stats).await;
    }

    debug!(
        ip = %orig_dst.ip(),
        port = orig_dst.port(),
        "original destination recovered"
    );

    relay_via_proxy(client, proxy_addr, orig_dst, stats).await
}

/// Relay directly to the destination, bypassing the upstream proxy.
async fn relay_direct(
    client: TcpStream,
    target: SocketAddrV4,
    stats: &Stats,
) -> io::Result<()> {
    client.set_nodelay(true)?;
    set_keepalive(&client);

    let upstream = TcpStream::connect(target).await?;
    upstream.set_nodelay(true)?;
    set_keepalive(&upstream);

    info!(
        ip = %target.ip(),
        port = target.port(),
        "direct passthrough (excluded from proxy)"
    );

    copy_both(client, upstream, stats).await
}

/// Establish a CONNECT tunnel through the upstream proxy and relay.
async fn relay_via_proxy(
    mut client: TcpStream,
    proxy_addr: SocketAddrV4,
    orig_dst: SocketAddrV4,
    stats: &Stats,
) -> io::Result<()> {
    client.set_nodelay(true)?;
    set_keepalive(&client);

    let mut proxy = TcpStream::connect(proxy_addr).await?;
    proxy.set_nodelay(true)?;
    set_keepalive(&proxy);

    let early_data = connect_handshake(&mut proxy, orig_dst).await?;

    info!(
        ip = %orig_dst.ip(),
        port = orig_dst.port(),
        "tunnel established"
    );

    if !early_data.is_empty() {
        // The proxy pipelined some tunneled data right after its 200 response.
        // Forward it to the client before entering the bidirectional copy.
        client.write_all(&early_data).await?;
    }

    copy_both(client, proxy, stats).await
}

/// Bidirectional copy between two streams; updates byte counters on success.
async fn copy_both(
    a: TcpStream,
    b: TcpStream,
    stats: &Stats,
) -> io::Result<()> {
    let (mut ar, mut aw) = io::split(a);
    let (mut br, mut bw) = io::split(b);

    let up = async {
        let r = io::copy(&mut ar, &mut bw).await;
        let _ = bw.shutdown().await;
        r
    };
    let down = async {
        let r = io::copy(&mut br, &mut aw).await;
        let _ = aw.shutdown().await;
        r
    };

    let (up_result, down_result) = tokio::join!(up, down);

    if let Ok(n) = &up_result {
        stats.add_up(*n);
    }
    if let Ok(n) = &down_result {
        stats.add_down(*n);
    }

    Ok(())
}

/// Parse a `host:port` string into its components.
///
/// Handles IPv4 (`1.2.3.4:80`), bracketed IPv6 (`[::1]:80`), and hostnames
/// (`proxy.example.com:80`). For hostnames, DNS resolution is performed by the
/// caller (e.g. via [`tokio::net::lookup_host`]).
pub fn parse_host_port(s: &str) -> Option<(String, u16)> {
    let colon = s.rfind(':')?;
    let host = s[..colon].to_string();
    let port: u16 = s[colon + 1..].parse().ok()?;
    if host.is_empty() || port == 0 {
        return None;
    }
    Some((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- parse_host_port ----------

    #[test]
    fn test_parse_host_port() {
        assert_eq!(
            parse_host_port("192.168.1.1:8080"),
            Some(("192.168.1.1".into(), 8080))
        );
        assert_eq!(parse_host_port("bad"), None);
        assert_eq!(parse_host_port(":8080"), None);
        assert_eq!(parse_host_port("host:"), None);
        assert_eq!(parse_host_port("host:0"), None);
        assert_eq!(parse_host_port("host:999999"), None);
    }

    #[test]
    fn test_parse_host_port_hostname() {
        assert_eq!(
            parse_host_port("proxy.example.com:8080"),
            Some(("proxy.example.com".into(), 8080))
        );
        assert_eq!(
            parse_host_port("localhost:3128"),
            Some(("localhost".into(), 3128))
        );
    }

    #[test]
    fn test_parse_host_port_bracketed_ipv6() {
        assert_eq!(
            parse_host_port("[::1]:8080"),
            Some(("[::1]".into(), 8080))
        );
    }

    // ---------- find_header_end ----------

    #[test]
    fn test_find_header_end() {
        let hdr = b"HTTP/1.1 200 OK\r\n\r\n";
        assert_eq!(find_header_end(hdr), Some(hdr.len()));
        let with_body = b"HTTP/1.1 200 OK\r\n\r\ndata";
        assert_eq!(find_header_end(with_body), Some(19));
        assert_eq!(find_header_end(b"partial"), None);
    }

    // ---------- parse_status_code ----------
    //
    // Regression coverage for the previous `header.contains(" 200 ")` check
    // which would reject `HTTP/1.1 200\r\n\r\n` (no reason phrase) and
    // accidentally accept any header containing the literal " 200 ".

    #[test]
    fn test_parse_status_code_ok_with_reason() {
        assert_eq!(parse_status_code("HTTP/1.1 200 OK\r\n"), Some(200));
        assert_eq!(
            parse_status_code("HTTP/1.0 200 Connection Established\r\n"),
            Some(200)
        );
    }

    #[test]
    fn test_parse_status_code_ok_no_reason() {
        // Trailing space + CRLF (reason phrase empty but SP present)
        assert_eq!(parse_status_code("HTTP/1.1 200 \r\n"), Some(200));
        // No reason, no trailing space — RFC-non-compliant but seen in the wild.
        assert_eq!(parse_status_code("HTTP/1.1 200\r\n"), Some(200));
    }

    #[test]
    fn test_parse_status_code_non_200() {
        assert_eq!(
            parse_status_code("HTTP/1.1 407 Proxy Authentication Required\r\n"),
            Some(407)
        );
        assert_eq!(
            parse_status_code("HTTP/1.1 502 Bad Gateway\r\n"),
            Some(502)
        );
        assert_eq!(parse_status_code("HTTP/1.1 503\r\n"), Some(503));
    }

    #[test]
    fn test_parse_status_code_malformed() {
        assert_eq!(parse_status_code(""), None);
        assert_eq!(parse_status_code("garbage"), None);
        assert_eq!(parse_status_code("HTTP/1.1\r\n"), None);
        assert_eq!(parse_status_code("HTTP/1.1 abc\r\n"), None);
    }

    #[test]
    fn test_parse_status_code_no_false_positive_on_substring() {
        // The old `header.contains(" 200 ")` would match this header that
        // mentions " 200 " in a header field but is not a 200 response.
        let header = "HTTP/1.1 418 I'm a teapot\r\nX-Note: see RFC 200 too\r\n\r\n";
        assert_eq!(parse_status_code(header), Some(418));
    }
}
